/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "AddressMatcher.h"
#include "InvertedMatcher.h"
#include "Matcher.h"
#include "Utils.h"

Proofpoint::AddressMatcher::AddressMatcher()
		:
		matchers({{SafeList::MatchType::EQUAL, std::make_shared<Matcher>(true, false, RE2::ANCHOR_BOTH)},
				{SafeList::MatchType::NOT_EQUAL, std::make_shared<InvertedMatcher>(true, false, RE2::ANCHOR_BOTH)},
				{SafeList::MatchType::MATCH, std::make_shared<Matcher>(true, false, RE2::UNANCHORED)},
				{SafeList::MatchType::NOT_MATCH, std::make_shared<InvertedMatcher>(true, false, RE2::UNANCHORED)},
				{SafeList::MatchType::REGEX, std::make_shared<Matcher>(false, false, RE2::UNANCHORED)},
				{SafeList::MatchType::NOT_REGEX,
						std::make_shared<InvertedMatcher>(false, false, RE2::UNANCHORED)}}) { };

void Proofpoint::AddressMatcher::Add(SafeList::MatchType type, const std::string& pattern, const std::size_t& index,
		PatternErrors& pattern_errors)
{
	if (type==MatchType::IS_IN_DOMAINSET || type==MatchType::UNKNOWN) return;

	switch (type) {
	case MatchType::IP_IN_NET: in_subnets.emplace_back();
		std::get<1>(in_subnets.back()) = 0;
		for (auto subnet : Utils::split(pattern, ',')) {
			std::get<0>(in_subnets.back()).emplace_back(std::make_shared<Subnet>(std::string(subnet)));
		}
		break;
	case MatchType::IP_NOT_IN_NET: not_in_subnets.emplace_back();
		std::get<1>(not_in_subnets.back()) = 0;
		for (auto subnet : Utils::split(pattern, ',')) {
			std::get<0>(not_in_subnets.back()).emplace_back(std::make_shared<Subnet>(std::string(subnet)));
		}
		break;
	default: matchers[type]->Add(pattern, index, pattern_errors);
		break;
	}
}
bool Proofpoint::AddressMatcher::Match(bool inbound, const std::string& pattern,
		std::vector<std::shared_ptr<SafeList::Entry>>& safe_list)
{
	bool matched = false;

	for (auto s : in_subnets) {
		// Find a single match per match condition
		for (const auto& subnet : std::get<0>(s))
			if (subnet->InSubnet(pattern)) {
				(inbound) ? safe_list[std::get<1>(s)]->inbound++ : safe_list[std::get<1>(s)]->outbound++;
				matched |= true;
				break;
			}
	}

	for (auto s : not_in_subnets) {
		// Find a single match per match condition
		for (const auto& subnet : std::get<0>(s))
			if (!subnet->InSubnet(pattern)) {
				(inbound) ? safe_list[std::get<1>(s)]->inbound++ : safe_list[std::get<1>(s)]->outbound++;
				matched |= true;
				break;
			}
	}

	std::vector<std::size_t> match_indexes;
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
