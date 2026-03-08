#pragma once

#include <functional>
#include <list>
#include <mutex>
#include <stdexcept>
#include <unordered_map>

namespace http_client {

//! A thread-safe LRU pool mapping keys to values.
//! When the pool exceeds max_size, the least-recently-used entry is evicted.
//! Used for connection pooling (cpr::Session per host) and rate limiters.
template <typename K, typename V>
class LRUPool {
public:
	//! @param max_size  maximum number of entries before LRU eviction kicks in
	explicit LRUPool(size_t max_size = 50) : max_size_(max_size) {
	}

	//! Get an existing entry or create a new one.
	//! The factory is called only if the key doesn't exist yet.
	//! Moves the entry to the front (most-recently-used) on every access.
	//! @param key      lookup key
	//! @param factory  callable that returns a V, invoked only on cache miss
	//! @return pointer to the value (owned by the pool, valid until evicted)
	template <typename Factory>
	V *GetOrCreate(const K &key, Factory factory) {
		std::lock_guard<std::mutex> lock(mutex_);

		auto it = index_.find(key);
		if (it != index_.end()) {
			// Move to front (most recently used)
			order_.splice(order_.begin(), order_, it->second);
			return &it->second->second;
		}

		// Evict LRU if at capacity
		if (order_.size() >= max_size_) {
			auto &evict_key = order_.back().first;
			index_.erase(evict_key);
			order_.pop_back();
		}

		// Insert new entry at front
		order_.emplace_front(key, factory());
		index_[key] = order_.begin();
		return &order_.front().second;
	}

	//! Get an existing entry, or nullptr if not found.
	V *Get(const K &key) {
		std::lock_guard<std::mutex> lock(mutex_);

		auto it = index_.find(key);
		if (it == index_.end()) {
			return nullptr;
		}
		// Move to front
		order_.splice(order_.begin(), order_, it->second);
		return &it->second->second;
	}

	//! Current number of entries.
	size_t Size() const {
		std::lock_guard<std::mutex> lock(mutex_);
		return order_.size();
	}

private:
	size_t max_size_;
	mutable std::mutex mutex_;

	// Doubly-linked list of (key, value) pairs, ordered most-recent to least-recent.
	std::list<std::pair<K, V>> order_;

	// Index from key into the list for O(1) lookup.
	std::unordered_map<K, typename std::list<std::pair<K, V>>::iterator> index_;
};

} // namespace http_client
