/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "GlobalAddressMatcher.h"
#include "Matcher.h"
#include "InvertedMatcher.h"
#include "SubnetMatcher.h"
#include "InvertedSubnetMatcher.h"

Proofpoint::GlobalAddressMatcher::GlobalAddressMatcher() :
       matchers({{GlobalList::MatchType::EQUAL, std::make_shared<Matcher<std::size_t>>(true, false, RE2::ANCHOR_BOTH)},
				{GlobalList::MatchType::NOT_EQUAL, std::make_shared<InvertedMatcher<std::size_t>>(true, false, RE2::ANCHOR_BOTH)},
				{GlobalList::MatchType::MATCH, std::make_shared<Matcher<std::size_t>>(true, false, RE2::UNANCHORED)},
				{GlobalList::MatchType::NOT_MATCH, std::make_shared<InvertedMatcher<std::size_t>>(true, false, RE2::UNANCHORED)},
				{GlobalList::MatchType::REGEX, std::make_shared<Matcher<std::size_t>>(false, false, RE2::UNANCHORED)},
				{GlobalList::MatchType::NOT_REGEX,std::make_shared<InvertedMatcher<std::size_t>>(false, false, RE2::UNANCHORED)},
       	        {GlobalList::MatchType::IP_IN_NET,std::make_shared<SubnetMatcher<std::size_t>>()},
       	        {GlobalList::MatchType::IP_NOT_IN_NET,std::make_shared<InvertedSubnetMatcher<std::size_t>>()}
       })
{ }

void Proofpoint::GlobalAddressMatcher::Add(GlobalList::MatchType type, const std::string& pattern, const std::size_t& index, PatternErrors<std::size_t>& pattern_errors)
{
	if (type==GlobalList::MatchType::IS_IN_DOMAINSET || type==GlobalList::MatchType::UNKNOWN) return;
	matchers[type]->Add(pattern, index, pattern_errors);
}

bool Proofpoint::GlobalAddressMatcher::Match(bool inbound, const std::string& pattern,GlobalList::Entries& safe_list)
{
	bool matched = false;
	std::vector<std::size_t> match_indexes;
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