/**
* This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#ifndef SLANALYZER_SUBNETMATCHER_H
#define SLANALYZER_SUBNETMATCHER_H

#include "IMatcher.h"
#include "SubnetSet.h"
#include "Utils.h"

#include <memory>
#include <unordered_map>
#include <iostream>

namespace Proofpoint
{
    template <typename T>
    class SubnetMatcher : public IMatcher<T>
    {
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
    void SubnetMatcher<T>::Add(const std::string& pattern,
                               const T& index,
                               PatternErrors<T>& pattern_errors)
    {
        for (const auto& cidr : Utils::split(pattern, ','))
        {
            std::string error;

            int id = subnet_set.Add(std::string(cidr), &error);

            if (id == -1)
            {
                pattern_errors.push_back({index, std::string(cidr), error});
                continue;
            }

            map_to_list_entry.insert({id, index});
        }
    }

    template <typename T>
    bool SubnetMatcher<T>::Match(const std::string& pattern,
                                 std::vector<T>& match_indexes)
    {
        match_indexes.clear();

        std::vector<int> matches;

        if (!subnet_set.Match(pattern, &matches))
        {
            return false;
        }

        for (int id : matches)
        {
            auto it = map_to_list_entry.find(id);

            if (it != map_to_list_entry.end())
            {
                match_indexes.emplace_back(it->second);
            }
        }

        return !match_indexes.empty();
    }

    template <typename T>
    std::size_t SubnetMatcher<T>::GetPatternCount()
    {
        return subnet_set.Size();
    }
}

#endif
