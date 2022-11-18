/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "StringMatcher.h"
#include "InvertedMatcher.h"
#include "Matcher.h"
#include <iostream>

Proofpoint::StringMatcher::StringMatcher()
		:
		matchers({{GlobalList::MatchType::EQUAL, std::make_shared<Matcher>(true, false, RE2::ANCHOR_BOTH)},
				{GlobalList::MatchType::NOT_EQUAL, std::make_shared<InvertedMatcher>(true, false, RE2::ANCHOR_BOTH)},
				{GlobalList::MatchType::MATCH, std::make_shared<Matcher>(true, false, RE2::UNANCHORED)},
				{GlobalList::MatchType::NOT_MATCH, std::make_shared<InvertedMatcher>(true, false, RE2::UNANCHORED)},
				{GlobalList::MatchType::REGEX, std::make_shared<Matcher>(false, false, RE2::UNANCHORED)},
				{GlobalList::MatchType::NOT_REGEX,
						std::make_shared<InvertedMatcher>(false, false, RE2::UNANCHORED)}}) { }
void Proofpoint::StringMatcher::Add(Proofpoint::GlobalList::MatchType type,
		const std::string& pattern,
		const size_t& index, PatternErrors& pattern_errors)
{

	if (type==GlobalList::MatchType::IS_IN_DOMAINSET || type==GlobalList::MatchType::UNKNOWN) return;

	matchers[type]->Add(pattern, index, pattern_errors);
}
inline bool Proofpoint::StringMatcher::Match(bool inbound, const std::string& pattern,
		std::vector<std::shared_ptr<GlobalList::Entry>>& safe_list)
{
	std::vector<std::size_t> match_indexes;
	bool matched = false;
	for (auto m : matchers) {
		if (m.second->GetPatternCount()) {
			matched |= m.second->Match(pattern, match_indexes);
			for (auto i : match_indexes) {
				auto mle = safe_list.at(i);
				(inbound) ? mle->inbound++ : mle->outbound++;
			}
		}
	}
	return matched;
}
