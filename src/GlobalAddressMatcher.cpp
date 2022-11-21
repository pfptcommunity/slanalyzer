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

Proofpoint::GlobalAddressMatcher::GlobalAddressMatcher() :
       matchers({{GlobalList::MatchType::EQUAL, std::make_shared<Matcher<std::size_t>>(true, false, RE2::ANCHOR_BOTH)},
				{GlobalList::MatchType::NOT_EQUAL, std::make_shared<InvertedMatcher<std::size_t>>(true, false, RE2::ANCHOR_BOTH)},
				{GlobalList::MatchType::MATCH, std::make_shared<Matcher<std::size_t>>(true, false, RE2::UNANCHORED)},
				{GlobalList::MatchType::NOT_MATCH, std::make_shared<InvertedMatcher<std::size_t>>(true, false, RE2::UNANCHORED)},
				{GlobalList::MatchType::REGEX, std::make_shared<Matcher<std::size_t>>(false, false, RE2::UNANCHORED)},
				{GlobalList::MatchType::NOT_REGEX,std::make_shared<InvertedMatcher<std::size_t>>(false, false, RE2::UNANCHORED)}})
{ };

void Proofpoint::GlobalAddressMatcher::Add(GlobalList::MatchType type, const std::string& pattern, const std::size_t& index, PatternErrors<std::size_t>& pattern_errors)
{
	if (type==GlobalList::MatchType::IS_IN_DOMAINSET || type==GlobalList::MatchType::UNKNOWN) return;

	switch (type) {
	case GlobalList::MatchType::IP_IN_NET:
		in_subnets.emplace_back();
		std::get<1>(in_subnets.back()) = index;
		for (auto subnet : Utils::split(pattern, ',')) {
			std::get<0>(in_subnets.back()).emplace_back(std::make_shared<Subnet>(std::string(subnet)));
		}
		break;
	case GlobalList::MatchType::IP_NOT_IN_NET:
		not_in_subnets.emplace_back();
		std::get<1>(not_in_subnets.back()) = index;
		for (auto subnet : Utils::split(pattern, ',')) {
			std::get<0>(not_in_subnets.back()).emplace_back(std::make_shared<Subnet>(std::string(subnet)));
		}
		break;
	default: matchers[type]->Add(pattern, index, pattern_errors);
		break;
	}
}
bool Proofpoint::GlobalAddressMatcher::Match(bool inbound, const std::string& pattern,GlobalList::Entries& safe_list)
{
	bool matched = false;
	for (auto s : in_subnets) {
		// Find a single match per match condition
		for (const auto& subnet : std::get<0>(s)) {
			if (subnet->InSubnet(pattern)) {
				(inbound) ? safe_list[std::get<1>(s)].inbound++ : safe_list[std::get<1>(s)].outbound++;
				matched |= true;
				break;
			}
		}
	}
	for (auto s : not_in_subnets) {
		// Find a single match per match condition
		for (const auto& subnet : std::get<0>(s))
			if (!subnet->InSubnet(pattern)) {
				(inbound) ? safe_list[std::get<1>(s)].inbound++ : safe_list[std::get<1>(s)].outbound++;
				matched |= true;
				break;
			}
	}
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