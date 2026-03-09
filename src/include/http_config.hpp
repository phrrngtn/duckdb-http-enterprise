#pragma once

#include <algorithm>
#include <nlohmann/json.hpp>
#include <string>

namespace http_client {

//! Extract hostname from a URL, lowercased. Returns empty string on failure.
inline std::string ExtractHostFromUrl(const std::string &url) {
	auto scheme_end = url.find("://");
	if (scheme_end == std::string::npos) return "";
	auto host_start = scheme_end + 3;
	// Skip userinfo@ if present
	auto at_pos = url.find('@', host_start);
	auto slash_pos = url.find('/', host_start);
	if (at_pos != std::string::npos && (slash_pos == std::string::npos || at_pos < slash_pos)) {
		host_start = at_pos + 1;
	}
	// Host ends at '/', ':', or '?' — whichever comes first
	auto host_end = url.find_first_of("/:?", host_start);
	if (host_end == std::string::npos) host_end = url.length();
	std::string host = url.substr(host_start, host_end - host_start);
	std::transform(host.begin(), host.end(), host.begin(), ::tolower);
	return host;
}

//! Resolved configuration for a single HTTP request.
//! Built by merging: per-call overrides > scope match > default > hard-coded fallbacks.
struct HttpConfig {
	double rate_limit_rps = 20.0;  // requests per second (parsed from rate_limit string)
	std::string rate_limit_spec = "20/s";
	double burst = 5.0;
	int timeout = 30;              // seconds
	bool verify_ssl = true;
	std::string proxy;             // empty = no proxy
	std::string ca_bundle;         // empty = system default
	std::string client_cert;       // empty = no client certificate
	std::string client_key;        // empty = no client key
	std::string auth_type;         // "negotiate", "bearer", or empty
	std::string bearer_token;      // for auth_type=bearer
	int64_t bearer_token_expires_at = 0; // Unix epoch seconds; 0 = no expiry check
	int max_concurrent = 10;       // max parallel requests in a scalar function chunk
	std::string global_rate_limit_spec; // empty = no global limit; only meaningful from "default" scope
	double global_burst = 10.0;

	//! Apply values from a JSON config object, overwriting only fields that are present.
	void MergeFrom(const nlohmann::json &j) {
		if (j.contains("rate_limit") && j["rate_limit"].is_string()) {
			rate_limit_spec = j["rate_limit"].get<std::string>();
		}
		if (j.contains("burst") && j["burst"].is_number()) {
			burst = j["burst"].get<double>();
		}
		if (j.contains("timeout") && j["timeout"].is_number()) {
			timeout = j["timeout"].get<int>();
		}
		if (j.contains("verify_ssl") && j["verify_ssl"].is_boolean()) {
			verify_ssl = j["verify_ssl"].get<bool>();
		}
		if (j.contains("proxy") && j["proxy"].is_string()) {
			proxy = j["proxy"].get<std::string>();
		}
		if (j.contains("ca_bundle") && j["ca_bundle"].is_string()) {
			ca_bundle = j["ca_bundle"].get<std::string>();
		}
		if (j.contains("client_cert") && j["client_cert"].is_string()) {
			client_cert = j["client_cert"].get<std::string>();
		}
		if (j.contains("client_key") && j["client_key"].is_string()) {
			client_key = j["client_key"].get<std::string>();
		}
		if (j.contains("auth_type") && j["auth_type"].is_string()) {
			auth_type = j["auth_type"].get<std::string>();
		}
		if (j.contains("bearer_token") && j["bearer_token"].is_string()) {
			bearer_token = j["bearer_token"].get<std::string>();
		}
		if (j.contains("bearer_token_expires_at") && j["bearer_token_expires_at"].is_number()) {
			bearer_token_expires_at = j["bearer_token_expires_at"].get<int64_t>();
		}
		if (j.contains("max_concurrent") && j["max_concurrent"].is_number()) {
			max_concurrent = j["max_concurrent"].get<int>();
			if (max_concurrent < 1) max_concurrent = 1;
		}
		if (j.contains("global_rate_limit") && j["global_rate_limit"].is_string()) {
			global_rate_limit_spec = j["global_rate_limit"].get<std::string>();
		}
		if (j.contains("global_burst") && j["global_burst"].is_number()) {
			global_burst = j["global_burst"].get<double>();
		}
	}
};

//! Resolve the HttpConfig for a given URL by reading the http_config variable.
//! The config_map_json is the result of querying getvariable('http_config') cast to JSON,
//! represented as a map of scope -> json-config-string.
//!
//! Resolution order:
//! 1. Hard-coded defaults (in HttpConfig struct)
//! 2. "default" key from the config map
//! 3. Longest matching scope prefix
//! 4. Per-call overrides (applied by the caller after this function returns)
inline HttpConfig ResolveConfig(const std::string &url,
                                const std::vector<std::pair<std::string, std::string>> &config_entries) {
	HttpConfig config;

	// Apply "default" entry first
	for (auto &[scope, json_str] : config_entries) {
		if (scope == "default") {
			try {
				config.MergeFrom(nlohmann::json::parse(json_str));
			} catch (...) {
				// Malformed JSON in default config — skip it
			}
			break;
		}
	}

	// Find longest matching scope: prefer prefix match, fall back to domain-suffix match
	std::string best_scope;
	std::string best_json;
	bool best_is_prefix = false;
	for (auto &[scope, json_str] : config_entries) {
		if (scope == "default") {
			continue;
		}
		// Prefix match: url starts with scope (e.g. https://api.example.com/v1 matches https://api.example.com/v1/users)
		if (url.rfind(scope, 0) == 0) {
			if (!best_is_prefix || scope.length() > best_scope.length()) {
				best_scope = scope;
				best_json = json_str;
				best_is_prefix = true;
			}
			continue;
		}
		// Domain-suffix match: scope's host is a suffix of url's host
		// (e.g. scope https://acmecorp.test matches url https://sub.acmecorp.test/path)
		if (!best_is_prefix) {
			auto scope_host = ExtractHostFromUrl(scope);
			auto url_host = ExtractHostFromUrl(url);
			if (!scope_host.empty() && !url_host.empty()) {
				bool matches = (url_host == scope_host) ||
				    (url_host.length() > scope_host.length() &&
				     url_host.compare(url_host.length() - scope_host.length(), scope_host.length(), scope_host) == 0 &&
				     url_host[url_host.length() - scope_host.length() - 1] == '.');
				if (matches && scope_host.length() > ExtractHostFromUrl(best_scope).length()) {
					best_scope = scope;
					best_json = json_str;
				}
			}
		}
	}

	// Apply the best scope match on top of defaults
	if (!best_scope.empty()) {
		try {
			config.MergeFrom(nlohmann::json::parse(best_json));
		} catch (...) {
			// Malformed JSON in scope config — skip it
		}
	}

	return config;
}

} // namespace http_client
