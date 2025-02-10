"""
SPDX-License-Identifier: MIT

  Copyright (c) 2025, SCANOSS

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
"""

import re
import unicodedata

FNV64_OFFSET_BASIS = 14695981039346656037
FNV64_PRIME = 1099511628211
MASK64 = 0xFFFFFFFFFFFFFFFF


def fnv1_64(data: bytes) -> int:
    """Compute the 64‐bit FNV‑1 hash of data."""
    h = FNV64_OFFSET_BASIS
    for b in data:
        h = (h * FNV64_PRIME) & MASK64
        h = h ^ b
    return h


class SimhashFeature:
    def __init__(self, hash_value: int, weight: int = 1):
        self.hash_value = hash_value
        self.weight = weight

    def sum(self) -> int:
        """Return the 64-bit hash (sum) of this feature."""
        return self.hash_value

    def get_weight(self) -> int:
        """Return the weight of this feature."""
        return self.weight


def new_feature(f: bytes) -> SimhashFeature:
    """Return a new feature for the given byte slice with weight 1."""
    return SimhashFeature(fnv1_64(f), 1)


def new_feature_with_weight(f: bytes, weight: int) -> SimhashFeature:
    """Return a new feature for the given byte slice with the given weight."""
    return SimhashFeature(fnv1_64(f), weight)


def vectorize(features: list) -> list:
    """
    Given a list of features, return a 64-element vector.
    Each feature contributes its weight to each coordinate,
    added if that bit is set and subtracted otherwise.
    """
    v = [0] * 64
    for feature in features:
        h = feature.sum()
        w = feature.get_weight()
        for i in range(64):
            if ((h >> i) & 1) == 1:
                v[i] += w
            else:
                v[i] -= w
    return v


def vectorize_bytes(features: list) -> list:
    """
    Given a list of byte slices, treat each as a feature (with weight 1)
    by computing its FNV-1 hash.
    """
    v = [0] * 64
    for feat in features:
        h = fnv1_64(feat)
        for i in range(64):
            if ((h >> i) & 1) == 1:
                v[i] += 1
            else:
                v[i] -= 1
    return v


def fingerprint(v: list) -> int:
    """
    Given a 64-element vector, return a 64-bit fingerprint.
    For each bit i, if v[i] >= 0, set bit i to 1; otherwise leave it 0.
    """
    f = 0
    for i in range(64):
        if v[i] >= 0:
            f |= 1 << i
    return f


def compare(a: int, b: int) -> int:
    """
    Calculate the Hamming distance between two 64-bit integers.
    (The number of differing bits.)
    """
    v = a ^ b
    c = 0
    while v:
        v &= v - 1
        c += 1
    return c


def simhash(fs) -> int:
    """
    Given a feature set (an object with a get_features() method),
    return its 64-bit simhash.
    """
    return fingerprint(vectorize(fs.get_features()))


def simhash_bytes(b: list) -> int:
    """
    Given a list of byte slices, return the simhash.
    """
    return fingerprint(vectorize_bytes(b))


boundaries = re.compile(rb"[\w']+(?:\://[\w\./]+){0,1}")
unicode_boundaries = re.compile(r"[\w'-]+", re.UNICODE)


# --- Helper Functions for Feature Extraction ---
def _get_features_bytes(b: bytes, pattern: re.Pattern) -> list:
    """
    Split the given byte string using the given regex pattern,
    and return a list of features (each created with new_feature).
    """
    words = pattern.findall(b)
    return [new_feature(word) for word in words]


def _get_features_str(s: str, pattern) -> list:
    """
    Split the given string using the given regex pattern,
    and return a list of features (each created by encoding to UTF-8).
    """
    words = pattern.findall(s)
    return [new_feature(word.encode('utf-8')) for word in words]


class WordFeatureSet:
    def __init__(self, b: bytes):
        # Normalize the input to lowercase.
        self.b = b.lower()

    def get_features(self) -> list:
        return _get_features_bytes(self.b, boundaries)


class UnicodeWordFeatureSet:
    def __init__(self, b: bytes, norm_form: str = 'NFC'):
        # Decode, normalize (using the provided form), and lowercase.
        text = b.decode('utf-8')
        normalized = unicodedata.normalize(norm_form, text)
        self.text = normalized.lower()

    def get_features(self) -> list:
        return _get_features_str(self.text, unicode_boundaries)


def shingle(w: int, b: list) -> list:
    """
    Return the w-shingling of the given set of byte slices.
    For example, if b is [b"this", b"is", b"a", b"test"]
    and w == 2, the result is [b"this is", b"is a", b"a test"].
    """
    if w < 1:
        raise ValueError('simhash.shingle(): k must be a positive integer')
    if w == 1:
        return b
    w = min(w, len(b))
    count = len(b) - w + 1
    shingles = []
    for i in range(count):
        shingles.append(b' '.join(b[i : i + w]))
    return shingles
