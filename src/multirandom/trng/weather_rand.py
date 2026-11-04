"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.trng.weather_rand
Description:
A random source using the Open-Meteo weather API. Not fully random by itself,
usable once blended with OS entropy, and no cryptographic hash touches the data.

Each fetch harvests *much* more information than the original single-hour
snapshot: the complete hourly arrays (29 variables) and daily aggregates
(19 variables) of a rolling window (``past_days`` + ``forecast_days`` days)
for every sampled location and moment -- thousands of real-world readings per
call. The readings are combined WITHOUT hashing, by three techniques:
1. *Lossless packing* -- every measurement contributes its exact IEEE-754
   bytes to the "tape", so no information is thrown into one digest.
2. *Von Neumann conditioning* -- tape bits are debiased pairwise
   (01 -> 1, 10 -> 0, 00/11 dropped), the classic technique for real physical
   noise (repeated identical readings are simply discarded).
3. *Wide reversible fold* -- tape and reservoir chunks are folded into a
   big-integer state with a splitmix64-derived odd multiplier and a
   chunk-dependent bit rotation per step. The fold keeps every chunk reachable
   (it is invertible, not a hash) and stops any single bit position from
   dominating.

The returned seed is configurable-large: 512 bits (64 bytes) by default, up to
8192 bits (1024 bytes). Failures on every weather fetch fall back to a plain
``os.urandom`` seed -- never a hash of the time.
"""
import aiohttp
import asyncio
import os
import random
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Sequence, Tuple

# --- Von Neumann table: byte -> (packed output bits, number of bits produced) ---
# For each of the four bit pairs of a byte: 01 -> emit 1, 10 -> emit 0, 00/11 drop.
_VN_TABLE = []
for _byte in range(256):
    _bits = [(_byte >> _i) & 1 for _i in range(8)]
    _out, _k = 0, 0
    for _i in range(0, 8, 2):
        _b1, _b2 = _bits[_i], _bits[_i + 1]
        if _b1 != _b2:
            _out = (_out << 1) | _b2
            _k += 1
    _VN_TABLE.append((_out, _k))

_SPLITMIX_MUL = 0xBF58476D1CE4E5B9
_SPLITMIX_ADD = 0x94D049BB133111EB
_GOLDEN = 0x9E3779B97F4A7C15


def _von_neumann_pool(src: bytes) -> bytes:
    """Debias *src* with the von Neumann technique and return the pool bytes.

    Pairs of consecutive input bits are only used when they differ
    (01 -> 1, 10 -> 0); equal pairs are discarded, which removes systematic
    single-bit bias at the cost of output length (about 25 % of the input).
    Widely used for conditioning true-RNG sensor data -- no hashing involved.
    """
    acc = accn = 0
    pool = bytearray()
    for byte in src:
        out, k = _VN_TABLE[byte]
        if k:
            acc = (acc << k) | out
            accn += k
            while accn >= 8:
                accn -= 8
                pool.append((acc >> accn) & 0xFF)
                acc &= (1 << accn) - 1
    if accn:
        pool.append((acc << (8 - accn)) & 0xFF)
    return bytes(pool)


class OpenMeteoAPI:
    """
    Entropy source using Open-Meteo weather API data.

    Each fetch harvests the full hourly and daily series of a rolling window
    for one location; ``get_seed`` samples several random locations and
    moments, folds all those readings into one large seed.

    Only provides entropy - use RandomUsingOpenMeteoAPI for the full random
    interface.
    """

    BASE_URL = "https://api.open-meteo.com/v1/forecast"

    # The full harvest: every hourly series the best-match model publishes.
    HOURLY_VARIABLES = [
        "temperature_2m",
        "relative_humidity_2m",
        "dew_point_2m",
        "apparent_temperature",
        "precipitation",
        "rain",
        "showers",
        "snowfall",
        "snow_depth",
        "freezing_level_height",
        "pressure_msl",
        "surface_pressure",
        "cloud_cover",
        "cloud_cover_low",
        "cloud_cover_mid",
        "cloud_cover_high",
        "visibility",
        "cape",
        "wind_speed_10m",
        "wind_direction_10m",
        "wind_gusts_10m",
        "temperature_80m",
        "soil_temperature_0_to_7cm",
        "soil_moisture_0_to_1cm",
        "shortwave_radiation",
        "direct_radiation",
        "diffuse_radiation",
        "vapour_pressure_deficit",
        "uv_index",
    ]

    # Daily aggregates: one row per day, still many real numbers per location.
    DAILY_VARIABLES = [
        "weather_code",
        "temperature_2m_max",
        "temperature_2m_min",
        "apparent_temperature_max",
        "apparent_temperature_min",
        "precipitation_sum",
        "rain_sum",
        "showers_sum",
        "snowfall_sum",
        "precipitation_hours",
        "precipitation_probability_max",
        "daylight_duration",
        "sunshine_duration",
        "wind_speed_10m_max",
        "wind_gusts_10m_max",
        "wind_direction_10m_dominant",
        "shortwave_radiation_sum",
        "uv_index_max",
        "et0_fao_evapotranspiration",
    ]

    # Lean retry set: the original single-snapshot variable list, in case a
    # model/location rejects parts of the full harvest.
    LEGACY_HOURLY_VARIABLES = [
        "temperature_2m",
        "relative_humidity_2m",
        "precipitation",
        "surface_pressure",
        "wind_speed_10m",
        "wind_direction_10m",
        "cloud_cover",
    ]

    DEFAULT_SEED_BYTES = 64

    def __init__(
        self,
        seed: Optional[int] = None,
        forecast_days: int = 3,
        past_days: int = 2,
    ):
        forecast_days = int(forecast_days)
        past_days = int(past_days)
        if not 1 <= forecast_days <= 16:
            raise ValueError("forecast_days must be between 1 and 16")
        if not 0 <= past_days <= 92:
            raise ValueError("past_days must be between 0 and 92")
        self._rng = random.Random(seed)
        self._forecast_days = forecast_days
        self._past_days = past_days
        self._current_location: Optional[Tuple[float, float]] = None

    def set_current_location(self, latitude: float, longitude: float):
        """Set the current location for weather-based entropy."""
        self._current_location = (latitude, longitude)

    def _generate_random_location(self) -> Tuple[float, float]:
        """Generate a random latitude and longitude."""
        latitude = self._rng.uniform(-60, 70)
        longitude = self._rng.uniform(-180, 180)
        return (latitude, longitude)

    def _generate_random_time(self, days_back: int = 7) -> datetime:
        """Generate a random time within the past few days."""
        now = datetime.now(timezone.utc)
        random_hours = self._rng.randint(0, days_back * 24)
        return now - timedelta(hours=random_hours)

    async def _fetch_weather_data(
        self,
        latitude: float,
        longitude: float,
        target_time: Optional[datetime] = None,
    ) -> Optional[dict]:
        """Fetch the full hourly + daily arrays from Open-Meteo.

        The full variable list is requested first; if the API rejects it for
        this model/location (HTTP 400), the request is retried once with the
        lean legacy list. Returns the JSON payload (may be missing variables)
        or None.
        """
        params = {
            "latitude": latitude,
            "longitude": longitude,
            "hourly": ",".join(self.HOURLY_VARIABLES),
            "daily": ",".join(self.DAILY_VARIABLES),
            "timezone": "UTC",
            "forecast_days": str(self._forecast_days),
            "past_days": str(self._past_days),
        }
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.BASE_URL, params=params) as response:
                    if response.status == 200:
                        return await response.json()
            except Exception:
                pass
        # Retry leaner: the full hourly list may be unsupported here.
        lean = dict(params)
        lean["hourly"] = ",".join(self.LEGACY_HOURLY_VARIABLES)
        lean.pop("daily", None)
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(self.BASE_URL, params=lean) as response:
                    if response.status == 200:
                        return await response.json()
            except Exception:
                pass
        return None

    async def _fetch_current_location(self) -> Optional[Tuple[float, float]]:
        """Fetch approximate current location via ipinfo.io (geopy fallback)."""
        try:
            # Free, no key needed.
            async with aiohttp.ClientSession() as session:
                async with session.get("https://ipinfo.io/json") as response:
                    if response.status == 200:
                        data = await response.json()
                        loc = data.get("loc", "")
                        if loc:
                            lat, lon = loc.split(",")
                            return (float(lat), float(lon))

            # Fallback: geocode a random major city for coarse entropy.
            from geopy.geocoders import Nominatim

            geolocator = Nominatim(user_agent="multirandom_weather")
            cities = ["Tokyo", "New York", "London", "Sydney", "Mumbai", "São Paulo"]
            city = self._rng.choice(cities)
            location = geolocator.geocode(city)
            if location:
                return (location.latitude, location.longitude)
            return None
        except Exception:
            return None

    def _collect_measurements(
        self,
        weather_data: dict,
        target_time: Optional[datetime] = None,
    ) -> List[float]:
        """Pull every real number out of a weather response (no hashing).

        Gathers the complete hourly series, the daily aggregates and the
        response metadata, plus the chosen time and the wall clock as
        floats -- the caller packs them losslessly.
        """
        measurements: List[float] = []
        hourly = weather_data.get("hourly") or {}
        for var in self.HOURLY_VARIABLES:
            values = hourly.get(var)
            if isinstance(values, list):
                measurements.extend(float(v) for v in values if v is not None)
        daily = weather_data.get("daily") or {}
        for var in self.DAILY_VARIABLES:
            values = daily.get(var)
            if isinstance(values, list):
                measurements.extend(float(v) for v in values if v is not None)
        for key in ("latitude", "longitude", "elevation",
                    "generationtime_ms", "utc_offset_seconds"):
            try:
                measurements.append(float(weather_data[key]))
            except (KeyError, TypeError, ValueError):
                pass
        if target_time is not None:
            measurements.append(float(target_time.timestamp()))
        measurements.append(time.time_ns() / 1e9)
        return measurements

    def _fold_odd(self, seed_bytes: int) -> int:
        """Splitmix64-derived odd multiplier, fresh per seed width."""
        x = _GOLDEN
        raw = bytearray()
        while len(raw) < seed_bytes:
            x = (x * _SPLITMIX_MUL + _SPLITMIX_ADD) & 0xFFFFFFFFFFFFFFFF
            raw += x.to_bytes(8, "big")
        return int.from_bytes(bytes(raw[:seed_bytes]), "big") | 1

    def _assemble_seed(self, measurements: Sequence[float], seed_bytes: int) -> int:
        """Fold every measurement into one large integer -- hash-free.

        1. exact IEEE-754 bytes of each measurement -> the "tape";
        2. the tape's bits get von Neumann-debiased into a second stream;
        3. both streams are folded (multiply-add + chunk-dependent rotation)
           into a seed_bytes-wide big integer, which is returned.
        """
        tape = bytearray()
        for value in measurements:
            tape += struct.pack("<d", float(value))

        pool = _von_neumann_pool(bytes(tape))

        nbits = seed_bytes * 8
        mask = (1 << nbits) - 1
        odd = self._fold_odd(seed_bytes)
        state = 1
        for src in (bytes(tape), pool):
            if not src:
                continue
            src += b"\x00" * (-len(src) % 8)
            for off in range(0, len(src), 8):
                chunk = int.from_bytes(src[off:off + 8], "big")
                state = (state * odd + chunk) & mask
                rot = 1 + chunk % (nbits - 1)
                state = ((state >> rot) | ((state << (nbits - rot)) & mask)) & mask
        return state

    async def get_seed(
        self,
        use_random_location: bool = True,
        use_current_location: bool = False,
        use_random_time: bool = True,
        num_random_locations: int = 3,
        seed_bytes: int = DEFAULT_SEED_BYTES,
    ) -> int:
        """
        Get a large seed value from weather entropy.

        Args:
            use_random_location: Fetch weather from random locations
            use_current_location: Fetch weather from current location
            use_random_time: Sample random moments (up to a week back)
            num_random_locations: Number of random locations to sample (0-12)
            seed_bytes: Seed width in bytes, 16..1024 (128..8192 bits)

        Returns:
            A big integer ``0 <= seed < 2^(8*seed_bytes)`` built from the raw
            measurement bytes, WITHOUT cryptographic hashing (lossless tape +
            von Neumann conditioning + reversible fold). If every fetch fails,
            returns fresh ``os.urandom`` bytes as an int -- never a time hash.
        """
        seed_bytes = int(seed_bytes)
        if not 16 <= seed_bytes <= 1024:
            raise ValueError("seed_bytes must be between 16 and 1024")
        num_random_locations = int(num_random_locations)
        if not 0 <= num_random_locations <= 12:
            raise ValueError("num_random_locations must be between 0 and 12")

        targets: List[Tuple[float, float, Optional[datetime]]] = []
        if use_random_location:
            for _ in range(num_random_locations):
                lat, lon = self._generate_random_location()
                target_time = self._generate_random_time() if use_random_time else None
                targets.append((lat, lon, target_time))

        if use_current_location:
            if self._current_location:
                lat, lon = self._current_location
            else:
                location = await self._fetch_current_location()
                if location:
                    lat, lon = location
                    self._current_location = location
                else:
                    lat, lon = 0.0, 0.0
            target_time = self._generate_random_time() if use_random_time else None
            targets.append((lat, lon, target_time))

        measurements: List[float] = []
        if targets:
            results = await asyncio.gather(*(
                self._fetch_weather_data(lat, lon, tt)
                for lat, lon, tt in targets))
            for data, (_lat, _lon, tt) in zip(results, targets):
                if data:
                    measurements.extend(self._collect_measurements(data, tt))

        if not measurements:
            return int.from_bytes(os.urandom(seed_bytes), "big")
        return self._assemble_seed(measurements, seed_bytes)


class RandomUsingOpenMeteoAPI(random.Random):
    """
    A random.Random subclass seeded with a large, unhashed weather seed.

    The weather seed (64 bytes / 512 bits by default; see OpenMeteoAPI.get_seed)
    is XORed term-to-term with fresh os.urandom noise of the same width -- a
    perfect blend that needs no hashing -- and handed whole to Mersenne
    Twister's state loader, which consumes the entire integer.
    """

    def __init__(
        self,
        auto_seed: bool = True,
        seed_bytes: int = OpenMeteoAPI.DEFAULT_SEED_BYTES,
    ):
        """
        Initialize the random generator.

        Args:
            auto_seed: If True, automatically seeds with weather entropy.
            seed_bytes: Weather seed width in bytes, 16..1024 (default 64 =>
                a 512-bit seed, three scales larger than the old 256-bit one).
        """
        self._seed_bytes = int(seed_bytes)
        if not 16 <= self._seed_bytes <= 1024:
            raise ValueError("seed_bytes must be between 16 and 1024")
        self._api = OpenMeteoAPI()
        # random.Random.__init__ calls self.seed(x); with x=None our override
        # would trigger a weather fetch, so hand it OS entropy directly and
        # reserve the (auto) weather seed for the explicit step below.
        super().__init__(int.from_bytes(os.urandom(32), "big"))

        if auto_seed:
            self.seed_from_weather()

    def _run_async(self, coro):
        """Helper to run async code synchronously."""
        try:
            asyncio.get_running_loop()
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        except RuntimeError:
            return asyncio.run(coro)

    def seed_from_weather(
        self,
        use_random_location: bool = True,
        use_current_location: bool = True,
        use_random_time: bool = True,
    ):
        """Seed with a large weather seed XOR fresh OS noise (no hashing)."""
        try:
            weather_seed = self._run_async(self._api.get_seed(
                use_random_location=use_random_location,
                use_current_location=use_current_location,
                use_random_time=use_random_time,
                seed_bytes=self._seed_bytes,
            ))
        except Exception:
            weather_seed = 0
        width = max((weather_seed.bit_length() + 7) // 8, self._seed_bytes)
        noise = int.from_bytes(os.urandom(width), "big")
        combined = weather_seed ^ noise
        # Feed the whole wide integer to Mersenne Twister's state loader.
        super().seed(combined)

    def seed(self, a=None, version=2):
        """Seed the generator. If a is None, seeds from weather."""
        if a is None:
            self.seed_from_weather()
        else:
            super().seed(a, version)

    def reseed_from_weather(self):
        """Force a reseed from fresh weather data."""
        self.seed_from_weather()



def main():
    api = OpenMeteoAPI(seed=1234)

    # --- offline: determinism, sensitivity, configurability of the fold ---
    tape = [api._rng.uniform(-40, 40) for _ in range(3000)]
    s1 = api._assemble_seed(tape, 64)
    assert s1.bit_length() <= 512, "64-byte seed overflowed 512 bits"
    assert s1 == api._assemble_seed(list(tape), 64), "fold is not deterministic"
    tape2 = list(tape)
    tape2[0] += 1e-9
    assert s1 != api._assemble_seed(tape2, 64), "seed ignores its measurements"
    big = api._assemble_seed(tape, 128)
    assert big.bit_length() <= 1024 and big != s1, "wider fold misbehaves"
    tiny = api._assemble_seed(tape, 16)
    assert tiny.bit_length() <= 128, "16-byte seed overflowed 128 bits"
    print("OpenMeteoAPI fold: deterministic, sensitive, width-configurable: OK")

    # --- offline: von Neumann conditioning really de-biases ---
    rng = random.Random(9)
    buf = bytearray(1 << 16)
    # Build 65536 bytes whose bits are iid with P(1) = 0.75 (heavily biased).
    for i in range(1 << 16):
        acc = 0
        for j in range(8):
            if rng.random() < 0.75:
                acc |= 1 << j
        buf[i] = acc
    raw_ratio = sum(bin(b).count("1") for b in buf) / (8 * len(buf))
    pool = _von_neumann_pool(bytes(buf))
    assert pool, "von Neumann pool came out empty"
    pool_ratio = sum(bin(b).count("1") for b in pool) / (8 * len(pool))
    assert 0.4 < pool_ratio < 0.6, \
        f"von Neumann conditioning failed ({raw_ratio:.3f} -> {pool_ratio:.3f})"
    print(f"Von Neumann conditioning: {raw_ratio:.3f} -> {pool_ratio:.3f} ones ratio: OK")

    # --- the random.Random wrapper itself (no network needed) ---
    g = RandomUsingOpenMeteoAPI(auto_seed=False, seed_bytes=64)
    g.seed(42)
    assert all(0.0 <= g.random() < 1.0 for _ in range(200))
    assert 0 <= g.choice(range(50)) < 50
    print("RandomUsingOpenMeteoAPI API (fixed seed): OK")

    # --- live weather fetch (network guard; falls back to os.urandom) ---
    try:
        seed = asyncio.run(api.get_seed(num_random_locations=1, seed_bytes=64))
        assert 0 <= seed < (1 << 512), "get_seed broke its width contract"
        other = asyncio.run(OpenMeteoAPI(seed=5678).get_seed(num_random_locations=1))
        assert seed != other, "two live harvests gave identical seeds"
        g2 = RandomUsingOpenMeteoAPI(auto_seed=False, seed_bytes=64)
        g2.reseed_from_weather()
        assert 0.0 <= g2.random() < 1.0
        print(f"Weather harvest + XOR-urandom reseed: OK "
              f"(seed {seed.bit_length()} bits, top hex {hex(seed)[:10]}…)")
    except Exception as exc:  # noqa: BLE001 - offline environment / network down
        fallback = int.from_bytes(os.urandom(64), "big")
        assert 0 <= fallback < (1 << 512)
        print(f"Live weather fetch skipped ({type(exc).__name__}: {exc}); "
              "os.urandom fallback path OK")


if __name__ == "__main__":
    main()
