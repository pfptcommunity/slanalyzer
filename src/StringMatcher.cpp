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
		matchers({{SafeList::MatchType::EQUAL, std::make_shared<Matcher>(true, false, RE2::ANCHOR_BOTH)},
				{SafeList::MatchType::NOT_EQUAL, std::make_shared<InvertedMatcher>(true, false, RE2::ANCHOR_BOTH)},
				{SafeList::MatchType::MATCH, std::make_shared<Matcher>(true, false, RE2::UNANCHORED)},
				{SafeList::MatchType::NOT_MATCH, std::make_shared<InvertedMatcher>(true, false, RE2::UNANCHORED)},
				{SafeList::MatchType::REGEX, std::make_shared<Matcher>(false, false, RE2::UNANCHORED)},
				{SafeList::MatchType::NOT_REGEX,
						std::make_shared<InvertedMatcher>(false, false, RE2::UNANCHORED)}}) { }
void Proofpoint::StringMatcher::Add(Proofpoint::SafeList::MatchType type,
		const std::string& pattern,
		const size_t& index, PatternErrors& errors)
{

	if (type==SBMatchType::IS_IN_DOMAINSET || type==SBMatchType::UNKNOWN) {
		std::cerr << "Unhandled MatchType" << std::endl;
		return;
	}
	matchers[type]->Add(pattern, index, errors);
}
bool Proofpoint::StringMatcher::Match(const std::string& pattern,
		std::vector<std::shared_ptr<SafeList::Entry>>& safe_list)
{
	bool matched = false;
	for (auto m : matchers) {
		std::vector<std::size_t> match_indexes;
		if (m.second->GetPatternCount()) {
			matched |= m.second->Match(pattern, match_indexes);
			for (auto i : match_indexes) {
				auto mle = safe_list.at(i);
				mle->matches++;
			}
		}
	}
	return matched;
}
