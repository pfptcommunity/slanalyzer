/**
* This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */

#include "SubnetSet.h"

#include <arpa/inet.h>
#include <exception>

namespace Proofpoint
{
    int SubnetSet::Add(const std::string& cidr, std::string* error)
    {
        try
        {
            const int id = next_id++;

            rules.emplace_back(ExactRule{
                .subnet = Subnet(cidr),
                .id = id,
                .prefix_length = 0
            });

            ExactRule* rule = &rules.back();

            rule->prefix_length =
                PrefixLength(rule->subnet.GetMaskAddress(Subnet::HOST));

            Insert(rule);

            return id;
        }
        catch (const std::exception& e)
        {
            if (error)
            {
                *error = e.what();
            }

            return -1;
        }
    }

    bool SubnetSet::Match(const std::string& ip, std::vector<int>* matches) const
    {
        if (matches)
        {
            matches->clear();
        }

        in_addr addr{};

        if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
        {
            return false;
        }

        return Match(ntohl(addr.s_addr), matches);
    }

    bool SubnetSet::Match(uint32_t ip_host_order, std::vector<int>* matches) const
    {
        if (matches)
        {
            matches->clear();
        }

        const auto octets = ToOctets(ip_host_order);
        const TrieNode* node = &root;

        for (uint8_t depth = 0; depth <= 4; ++depth)
        {
            for (const ExactRule* rule : node->exact_rules)
            {
                if (matches)
                {
                    matches->push_back(rule->id);
                }
            }

            if (depth == 4)
            {
                break;
            }

            const uint8_t next_octet = octets[depth];

            for (const auto& partial : node->partial_rules)
            {
                if (MatchesPartial(next_octet, partial))
                {
                    if (matches)
                    {
                        matches->push_back(partial.rule->id);
                    }
                }
            }

            const auto& child = node->children[next_octet];

            if (!child)
            {
                break;
            }

            node = child.get();
        }

        return matches && !matches->empty();
    }

    std::size_t SubnetSet::Size() const
    {
        return rules.size();
    }

    void SubnetSet::Insert(ExactRule* rule)
    {
        const uint32_t network = rule->subnet.GetNetAddress(Subnet::HOST);
        const auto octets = ToOctets(network);

        const uint8_t full_octets = rule->prefix_length / 8;
        const uint8_t remaining_bits = rule->prefix_length % 8;

        TrieNode* node = &root;

        for (uint8_t i = 0; i < full_octets; ++i)
        {
            const uint8_t value = octets[i];

            if (!node->children[value])
            {
                node->children[value] = std::make_unique<TrieNode>();
            }

            node = node->children[value].get();
        }

        if (remaining_bits == 0)
        {
            node->exact_rules.push_back(rule);
            return;
        }

        const uint8_t next_octet = octets[full_octets];
        const uint8_t mask = PartialMask(remaining_bits);

        node->partial_rules.push_back(PartialRule{
            .remaining_bits = remaining_bits,
            .masked_value = static_cast<uint8_t>(next_octet & mask),
            .rule = rule
        });
    }

    bool SubnetSet::MatchesPartial(uint8_t octet, const PartialRule& partial)
    {
        const uint8_t mask = PartialMask(partial.remaining_bits);
        return static_cast<uint8_t>(octet & mask) == partial.masked_value;
    }

    uint8_t SubnetSet::PartialMask(uint8_t bits)
    {
        return static_cast<uint8_t>(0xFFu << (8 - bits));
    }

    uint8_t SubnetSet::PrefixLength(uint32_t mask)
    {
        uint8_t bits = 0;

        while (mask & 0x80000000u)
        {
            ++bits;
            mask <<= 1;
        }

        return bits;
    }

    std::array<uint8_t, 4> SubnetSet::ToOctets(uint32_t ip)
    {
        return {
            static_cast<uint8_t>((ip >> 24) & 0xFFu),
            static_cast<uint8_t>((ip >> 16) & 0xFFu),
            static_cast<uint8_t>((ip >> 8) & 0xFFu),
            static_cast<uint8_t>(ip & 0xFFu)
        };
    }
}
