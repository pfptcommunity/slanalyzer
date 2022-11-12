#ifndef SLPARSER_IPMATCHER_H
#define SLPARSER_IPMATCHER_H

#include "re2/re2.h"
#include "re2/set.h"
#include "Subnet.h"
#include "Matcher.h"
#include "InvertedMatcher.h"
#include "SafeList.h"
#include <vector>
#include <string>
#include <tuple>
#include <map>

namespace Proofpoint {
	class IPMatcher {
	public:
		IPMatcher()
				:
				equal(true, false, RE2::ANCHOR_BOTH),
				not_equal(true, false, RE2::ANCHOR_BOTH),
				match(true, false, RE2::UNANCHORED),
				not_match(true, false, RE2::UNANCHORED),
				regex(false, false, RE2::UNANCHORED),
				not_regex(false, false, RE2::UNANCHORED) { }

		void Add(SafeList::SBMatchType type, std::string pattern, const std::size_t& index)
		{
			using
			enum SafeList::SBMatchType;
			switch (type) {
			case EQUAL:
				equal.Add(pattern, index);
				break;
			case NOT_EQUAL:
				not_equal.Add(pattern, index);
				break;
			case MATCH:
				match.Add(pattern, index);
				break;
			case NOT_MATCH:
				not_match.Add(pattern, index);
				break;
			case REGEX:
				regex.Add(pattern, index);
				break;
			case NOT_REGEX:
				not_regex.Add(pattern, index);
				break;
			case IP_IN_NET:
				in_subnets.emplace_back(std::make_shared<Subnet>(pattern), index);
				break;
			case IP_NOT_IN_NET:
				not_in_subnets.emplace_back(std::make_shared<Subnet>(pattern), index);
				break;
			case IS_IN_DOMAINSET:
				break;
			default:
				std::cerr << "Unknown, match type." << std::endl;
				break;
			}
		}

		bool Match(const std::string& pattern, std::vector<std::shared_ptr<SafeList::SLEntry>>& safe_list)
		{
			bool matched = false;
			std::vector<std::size_t> match_indexes;

			if (equal.GetPatternCount()) {
				matched |= equal.Match(pattern, match_indexes);
				for (auto i: match_indexes) {
					auto mle = safe_list.at(i);
					mle->matches++;
				}
			}

			if (match.GetPatternCount()) {
				matched |= match.Match(pattern, match_indexes);
				for (auto i: match_indexes) {
					auto mle = safe_list.at(i);
					mle->matches++;
				}
			}

			if (regex.GetPatternCount()) {
				matched |= regex.Match(pattern, match_indexes);
				for (auto i: match_indexes) {
					auto mle = safe_list.at(i);
					mle->matches++;
				}
			}

			for (auto s: in_subnets) {
				auto ptr = std::get<0>(s);
				auto index = std::get<1>(s);
				if (ptr->InSubnet(pattern)) {
					safe_list[index]->matches++;
					matched |= true;
				}
			}

			if (not_equal.GetPatternCount()) {
				if (!not_equal.Match(pattern, match_indexes)) {
					for (auto i: match_indexes) {
						auto mle = safe_list.at(i);
						mle->matches++;
						matched |= true;
					}
				}
			}

			if (not_match.GetPatternCount()) {
				if (!not_match.Match(pattern, match_indexes)) {
					for (auto i: match_indexes) {
						auto mle = safe_list.at(i);
						mle->matches++;
						matched |= true;
					}
				}
			}

			if (not_regex.GetPatternCount()) {
				if (!not_regex.Match(pattern, match_indexes)) {
					for (auto i: match_indexes) {
						auto mle = safe_list.at(i);
						mle->matches++;
						matched |= true;
					}
				}
			}
			return matched;
		}

	private:
		Matcher equal;
		InvertedMatcher not_equal;
		Matcher match;
		InvertedMatcher not_match;
		Matcher regex;
		InvertedMatcher not_regex;
		std::vector<std::tuple<std::shared_ptr<Subnet>, std::size_t>> in_subnets;
		std::vector<std::tuple<std::shared_ptr<Subnet>, std::size_t>> not_in_subnets;
	};
}
#endif //SLPARSER_IPMATCHER_H