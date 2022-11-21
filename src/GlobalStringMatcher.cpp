/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "GlobalStringMatcher.h"
#include "Matcher.h"
#include "InvertedMatcher.h"

Proofpoint::GlobalStringMatcher::GlobalStringMatcher()
		:
		matchers({{GlobalList::MatchType::EQUAL, std::make_shared<Matcher<std::size_t>>(true, false, RE2::ANCHOR_BOTH)},
				{GlobalList::MatchType::NOT_EQUAL, std::make_shared<InvertedMatcher<std::size_t>>(true, false, RE2::ANCHOR_BOTH)},
				{GlobalList::MatchType::MATCH, std::make_shared<Matcher<std::size_t>>(true, false, RE2::UNANCHORED)},
				{GlobalList::MatchType::NOT_MATCH, std::make_shared<InvertedMatcher<std::size_t>>(true, false, RE2::UNANCHORED)},
				{GlobalList::MatchType::REGEX, std::make_shared<Matcher<std::size_t>>(false, false, RE2::UNANCHORED)},
				{GlobalList::MatchType::NOT_REGEX,std::make_shared<InvertedMatcher<std::size_t>>(false, false, RE2::UNANCHORED)}})
{ }
void Proofpoint::GlobalStringMatcher::Add(Proofpoint::GlobalList::MatchType type, const std::string& pattern, const std::size_t& index, PatternErrors<std::size_t>& pattern_errors)
{
	if (type==GlobalList::MatchType::IS_IN_DOMAINSET || type==GlobalList::MatchType::UNKNOWN) return;
	matchers[type]->Add(pattern, index, pattern_errors);
}
bool Proofpoint::GlobalStringMatcher::Match(bool inbound, const std::string& pattern, GlobalList::Entries& safe_list)
{
	std::vector<std::size_t> match_indexes;
	bool matched = false;
	for (auto m : matchers) {
		if (m.second->GetPatternCount()) {
			matched |= m.second->Match(pattern, match_indexes);
			for (auto i : match_indexes) {
				(inbound) ? safe_list[i].inbound++ : safe_list[i].outbound++;
			}
		}
	}
	return matched;
}

bool Proofpoint::GlobalStringMatcher::Match(bool inbound, const std::vector<std::basic_string_view<char>>& patterns, GlobalList::Entries& safe_list)
{
	std::vector<std::size_t> match_indexes;
	bool matched = false;
	for (auto m : matchers) {
		if (m.second->GetPatternCount()) {
			for( const auto& pattern : patterns ) {
				matched |= m.second->Match(std::string(pattern), match_indexes);
				for (auto i : match_indexes) {
					(inbound) ? safe_list[i].inbound++ : safe_list[i].outbound++;
				}
			}
		}
	}
	return matched;
}
