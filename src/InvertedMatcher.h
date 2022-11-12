#ifndef SLPARSER_INVERTEDMATCHER_H
#define SLPARSER_INVERTEDMATCHER_H

#include "re2/re2.h"
#include "re2/set.h"
#include "SafeList.h"

namespace Proofpoint {
	class InvertedMatcher {
	public:
		InvertedMatcher(bool literal = false, bool case_sensitive = false, RE2::Anchor anchor = re2::RE2::ANCHOR_BOTH)
		{
			compiled = false;
			opt.set_literal(literal);
			opt.set_case_sensitive(case_sensitive);
			match = std::make_unique<RE2::Set>(opt, anchor);
		}

		void Add(const std::string& pattern, const std::size_t& index)
		{
			int i = match->Add(pattern, NULL);
			map_to_sle.insert({ i, index });
		}

		bool Match(const std::string& pattern, std::vector<std::size_t>& match_indexes)
		{
			match_indexes.clear();
			if (!compiled) {
				match->Compile();
				compiled = true;
			}
			std::vector<int> m;
			bool matched = !match->Match(pattern, &m);
			for (auto item: map_to_sle) {
				if (!std::binary_search(m.begin(), m.end(), item.first)) {
					match_indexes.emplace_back(item.second);
				}
			}
			return matched;
		}

		std::size_t GetPatternCount()
		{
			return map_to_sle.size();
		}

	private:
		bool compiled;
		RE2::Options opt;
		std::unique_ptr<RE2::Set> match;
		std::map<int, std::size_t> map_to_sle;
	};
}
#endif //SLPARSER_INVERTEDMATCHER_H
