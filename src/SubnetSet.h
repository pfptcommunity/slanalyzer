/**
* This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */

#ifndef SLANALYZER_SUBNETSET_H
#define SLANALYZER_SUBNETSET_H

#include "Subnet.h"

#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <vector>

namespace Proofpoint
{
    class SubnetSet
    {
    public:
        SubnetSet() = default;

        int Add(const std::string& cidr, std::string* error);

        bool Match(const std::string& ip, std::vector<int>* matches) const;

        bool Match(uint32_t ip_host_order, std::vector<int>* matches) const;

        [[nodiscard]]
        std::size_t Size() const;

    private:
        struct ExactRule
        {
            Subnet subnet;
            int id{};
            uint8_t prefix_length{};
        };

        struct PartialRule
        {
            uint8_t remaining_bits{};
            uint8_t masked_value{};
            const ExactRule* rule{};
        };

        struct TrieNode
        {
            std::array<std::unique_ptr<TrieNode>, 256> children{};
            std::vector<const ExactRule*> exact_rules;
            std::vector<PartialRule> partial_rules;
        };

    private:
        void Insert(ExactRule* rule);

        static bool MatchesPartial(uint8_t octet, const PartialRule& partial);

        static uint8_t PartialMask(uint8_t bits);

        static uint8_t PrefixLength(uint32_t mask);

        static std::array<uint8_t, 4> ToOctets(uint32_t ip);

    private:
        TrieNode root;
        std::deque<ExactRule> rules;
        int next_id{0};
    };
}

#endif
