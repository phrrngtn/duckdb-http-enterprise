#pragma once

#include "lru_pool.hpp"

#include <chrono>
#include <stdexcept>
#include <string>

namespace http_client {

//! GCRA (Generic Cell Rate Algorithm) rate limiter.
//! Tracks a single timestamp (the Theoretical Arrival Time) per key.
//! No background threads, no token counters — just one time_point and arithmetic.
class GCRARateLimiter {
public:
	//! Construct a rate limiter.
	//! @param rate      requests per second
	//! @param burst     maximum burst size (requests that can arrive at once)
	GCRARateLimiter(double rate, double burst)
	    : interval_(1.0 / rate), burst_offset_(interval_ * burst), tat_(std::chrono::steady_clock::now()) {
	}

	//! Try to acquire permission for one request.
	//! Returns true if allowed, false if rate limit exceeded.
	bool TryAcquire() {
		auto now = std::chrono::steady_clock::now();
		// If TAT is in the past, reset to now (we haven't been using our allowance)
		auto new_tat = (tat_ < now) ? now : tat_;
		// How far into the future would the new TAT be?
		auto diff = std::chrono::duration<double>(new_tat - now).count() + interval_;
		if (diff > burst_offset_) {
			return false;
		}
		tat_ = std::chrono::time_point_cast<std::chrono::steady_clock::duration>(
		    new_tat + std::chrono::duration<double>(interval_));
		return true;
	}

	//! Returns how long the caller should wait before retrying (seconds).
	//! Returns 0.0 if a request would be allowed right now.
	double WaitTime() const {
		auto now = std::chrono::steady_clock::now();
		auto wait = std::chrono::duration<double>(tat_ - now).count();
		return (wait > 0.0) ? wait : 0.0;
	}

private:
	double interval_;     // seconds between requests (1/rate)
	double burst_offset_; // max burst window in seconds (interval * burst)
	std::chrono::steady_clock::time_point tat_; // theoretical arrival time
};

//! Parse a rate limit string like "10/s", "100/m", "1000/h" into requests-per-second.
//! Returns 0.0 if the string is empty (meaning no rate limit).
inline double ParseRateLimit(const std::string &spec) {
	if (spec.empty()) {
		return 0.0;
	}

	auto slash = spec.find('/');
	if (slash == std::string::npos || slash == 0 || slash == spec.length() - 1) {
		throw std::runtime_error("Invalid rate_limit format: '" + spec + "'. Expected format: '10/s', '100/m', or '1000/h'");
	}

	double count;
	try {
		count = std::stod(spec.substr(0, slash));
	} catch (...) {
		throw std::runtime_error("Invalid rate_limit count in: '" + spec + "'");
	}

	auto unit = spec.substr(slash + 1);
	double divisor;
	if (unit == "s" || unit == "sec") {
		divisor = 1.0;
	} else if (unit == "m" || unit == "min") {
		divisor = 60.0;
	} else if (unit == "h" || unit == "hr") {
		divisor = 3600.0;
	} else {
		throw std::runtime_error("Invalid rate_limit unit '" + unit + "' in: '" + spec + "'. Use s, m, or h.");
	}

	return count / divisor;
}

//! Default rate limit applied when no scoped secret overrides it.
//! Prevents accidental server hammering from unbounded queries.
static constexpr const char *DEFAULT_RATE_LIMIT = "20/s";
static constexpr double DEFAULT_BURST = 5.0;

//! Thread-safe registry of per-host rate limiters backed by an LRU pool.
//! If no secret provides a rate_limit for a host, the session-wide default (20/s) applies.
class RateLimiterRegistry {
public:
	explicit RateLimiterRegistry(size_t max_hosts = 200) : pool_(max_hosts) {
	}

	//! Get or create a rate limiter for the given host.
	//! @param host       hostname key
	//! @param rate_spec  rate limit string from a scoped secret, or empty to use the default
	//! @param burst      burst capacity, used only on first creation
	//! @return pointer to the rate limiter (never null — the default always applies)
	GCRARateLimiter *GetOrCreate(const std::string &host, const std::string &rate_spec = "",
	                             double burst = DEFAULT_BURST) {
		return pool_.GetOrCreate(host, [&]() {
			double rate = ParseRateLimit(rate_spec.empty() ? DEFAULT_RATE_LIMIT : rate_spec);
			return GCRARateLimiter(rate, burst);
		});
	}

private:
	LRUPool<std::string, GCRARateLimiter> pool_;
};

} // namespace http_client
