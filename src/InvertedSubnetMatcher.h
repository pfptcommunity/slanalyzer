/**
* This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLANALYZER_INVERTEDSUBNETMATCHER_H
#define SLANALYZER_INVERTEDSUBNETMATCHER_H

#include "IMatcher.h"
#include "SubnetSet.h"
#include "Utils.h"

#include <unordered_map>
#include <unordered_set>
#include <iostream>

namespace Proofpoint {

    template <typename T>
    class InvertedSubnetMatcher : public IMatcher<T> {
    public:
        void Add(const std::string& pattern,
                 const T& index,
                 PatternErrors<T>& pattern_errors) override;

        bool Match(const std::string& pattern,
                   std::vector<T>& match_indexes) override;

        std::size_t GetPatternCount() override;

    private:
        SubnetSet subnet_set;
        std::unordered_map<int, T> map_to_list_entry;
    };

    template <typename T>
    void InvertedSubnetMatcher<T>::Add(const std::string& pattern,
                               const T& index,
                               PatternErrors<T>& pattern_errors)
    {
        for (const auto& cidr : Utils::split(pattern, ',')) {
            std::string error;

            int id = subnet_set.Add(std::string(cidr), &error);

            if (id == -1) {
                pattern_errors.push_back({index, std::string(cidr), error});
                continue;
            }

            map_to_list_entry.insert({id, index});
        }
    }

    template <typename T>
    bool InvertedSubnetMatcher<T>::Match(const std::string& pattern,
                                 std::vector<T>& match_indexes)
    {
        match_indexes.clear();
        match_indexes.reserve(map_to_list_entry.size());

        std::vector<int> matches;

        bool matched = !subnet_set.Match(pattern, &matches);

        if (matches.empty())
        {
            for (const auto& item : map_to_list_entry) {
                match_indexes.emplace_back(item.second);
            }
            return matched;
        }

        std::unordered_set<int> matched_set(matches.begin(), matches.end());

        for (const auto& item : map_to_list_entry) {
            if (matched_set.find(item.first) == matched_set.end()) {
                match_indexes.emplace_back(item.second);
            }
        }

        return matched;
    }

    template <typename T>
    std::size_t InvertedSubnetMatcher<T>::GetPatternCount()
    {
        return subnet_set.Size();
    }

}

#endif