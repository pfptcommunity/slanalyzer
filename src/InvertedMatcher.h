/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLANALYZER_INVERTEDMATCHER_H
#define SLANALYZER_INVERTEDMATCHER_H

#include "IMatcher.h"
#include "re2/re2.h"
#include "re2/set.h"
#include <memory>
#include <unordered_map>

namespace Proofpoint {
template <typename T>
class InvertedMatcher : public IMatcher<T> {
public:
	explicit InvertedMatcher(bool literal = false, bool case_sensitive = false, RE2::Anchor anchor = RE2::ANCHOR_BOTH);
	~InvertedMatcher() { delete match; }
public:
	void Add(const std::string& pattern, const T& index, PatternErrors<T>& pattern_errors) override;
	bool Match(const std::string& pattern, std::vector<T>& match_indexes) override;
	std::size_t GetPatternCount() override;
private:
	bool compiled;
	bool compile_failed;
	RE2::Options opt;
	RE2::Set* match;
	std::unordered_map<int, T> map_to_global_list;
};


template<typename T>
Proofpoint::InvertedMatcher<T>::InvertedMatcher(bool literal, bool case_sensitive, RE2::Anchor anchor) : compiled(false), compile_failed(false)
{
	opt.set_literal(literal);
	opt.set_case_sensitive(case_sensitive);
	opt.set_log_errors(false);
	// Set max memory to 16mb per pattern
	opt.set_max_mem(16777216);
	match = new RE2::Set(opt, anchor);
}

template<typename T>
void Proofpoint::InvertedMatcher<T>::Add(const std::string& pattern, const T& index, PatternErrors<T>& pattern_errors)
{
	std::string error;
	int i = match->Add(pattern, &error);
	if (i==-1) {
		pattern_errors.push_back({index, pattern, error});
		return;
	}
	map_to_global_list.insert({i, index});
}

template<typename T>
bool Proofpoint::InvertedMatcher<T>::Match(const std::string& pattern, std::vector<T>& match_indexes)
{
	match_indexes.clear();
	if (!compiled) {
		compile_failed = match->Compile();
		compiled = true;
	}

	if( !compile_failed ) {
		std::cerr << "Failed to compile" << std::endl;
		return false;
	}

	std::vector<int> m;
	bool matched = !match->Match(pattern, &m);
	for (auto item : map_to_global_list) {
		if (!std::binary_search(m.begin(), m.end(), item.first)) {
			match_indexes.emplace_back(item.second);
		}
	}
	return matched;
}
template<typename T>
std::size_t Proofpoint::InvertedMatcher<T>::GetPatternCount()
{
	return map_to_global_list.size();
}


}
#endif //SLANALYZER_INVERTEDMATCHER_H
