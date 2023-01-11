/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */

#include "UserList.h"
#include "CsvParser.h"
#include <iostream>
#include <numeric>
#include "Utils.h"

Proofpoint::UserList::UserList() :user_address_count(0), safe_list_count(0), block_list_count(0) {}

void Proofpoint::UserList::Load(const std::string& user_file, UserErrors& entry_errors)
{
	user_address_count = 0;
	std::size_t line_number = 0;
	std::ifstream f(user_file);
	csv::CsvParser parser(f);
	csv::HeaderMap header_map;
	csv::HeaderList required_headers{
			"mailLocalAddress",
			"safelist",
			"blocklist",
			"givenName",
			"sn",
			"mail"};

	// Validate there are headers we are interested in...
	csv::HeaderIndex header_index = parser.FindHeader(required_headers, header_map);

	if (header_index != -1)
		for (const auto& row : parser) {
			line_number++;
			size_t cols = row.size();

			// Skip empty lines
			if( cols == 1 && Utils::trim_copy(row.at(0)).empty() )
				continue;

			// Should add some logic to make sure that the column numbers exist
			entries.emplace_back();
			entries.back().line_number = line_number;
			entries.back().givenName = row[header_map.find("givenName")->second];
			entries.back().sn = row[header_map.find("sn")->second];
			entries.back().mail = row[header_map.find("mail")->second];
			entries.back().safe_count = 0;
			entries.back().block_count = 0;
			user_address_count++;
			for (auto proxy_address : Utils::split(row[header_map.find("mailLocalAddress")->second], ';')) {
				entries.back().proxy_addresses.emplace_back(proxy_address);
				user_address_count++;
			}
			for (auto safe_entry : Utils::split(row[header_map.find("safelist")->second], ';')) {
				entries.back().safe.emplace_back(std::string(safe_entry));
				safe_list_count++;
			}
			for (auto block_entry : Utils::split(row[header_map.find("blocklist")->second], ';')) {
				entries.back().block.emplace_back(std::string(block_entry));
				block_list_count++;
			}
		}
}

void Proofpoint::UserList::Save(const std::string& user_file, bool extended)
{
	std::ios_base::sync_with_stdio(false);
	if( !extended ) {
		std::ofstream f(user_file);
		f << "\"" << "givenName"
		  << "\",\"" << "sn"
		  << "\",\"" << "mail"
		  << "\",\"" << "mailLocalAddress"
		  << "\",\"" << "safelist"
		  << "\",\"" << "blocklist"
		  << "\",\"" << "safe_list_count"
		  << "\",\"" << "block_list_count" << "\"\r\n";

		auto acc = [](const std::string& a, const Entry::ListItem& b) -> std::string {
		  return a+(a.size()>0 ? ";" : "")+b.pattern;
		};

		for (const auto& user : entries) {
			f << "\"" << user.givenName
			  << "\",\"" << user.sn
			  << "\",\"" << user.mail
			  << "\",\"" << std::accumulate(user.proxy_addresses.begin(), user.proxy_addresses.end(), std::string(),
					[](const std::string& a, const std::string& b) -> std::string {
					  return a+(a.size()>0 ? ";" : "")+b;
					})
			  << "\",\"" << std::accumulate(user.safe.begin(), user.safe.end(), std::string(), acc)
			  << "\",\"" << std::accumulate(user.block.begin(), user.block.end(), std::string(), acc)
			  << "\",\"" << user.safe_count
			  << "\",\"" << user.block_count
			  << "\"\r\n";
		}
	}
	else {
		std::ofstream f(user_file);
		f << "\"" << "givenName"
		  << "\",\"" << "sn"
		  << "\",\"" << "mail"
		  << "\",\"" << "mailLocalAddress"
		  << "\",\"" << "safe"
		  << "\",\"" << "safe_sender"
		  << "\",\"" << "safe_hfrom"
		  << "\",\"" << "block"
		  << "\",\"" << "block_sender"
		  << "\",\"" << "block_hfrom" << "\"\r\n";
		for (const auto& user : entries) {
			for (const auto& safe : user.safe) {
				f << "\"" << user.givenName
				  << "\",\"" << user.sn
				  << "\",\"" << user.mail
				  << "\",\""
				  << std::accumulate(user.proxy_addresses.begin(), user.proxy_addresses.end(), std::string(),
						  [](const std::string& a, const std::string& b) -> std::string {
							return a+(a.size()>0 ? ";" : "")+b;
						  })
				  << "\",\"" << safe.pattern
				  << "\",\"" << safe.sender_count
				  << "\",\"" << safe.hfrom_count
				  << "\",\""
				  << "\",\"" << 0
				  << "\",\"" << 0
				  << "\"\r\n";
			}
			for (const auto& block : user.block) {
				f << "\"" << user.givenName
				  << "\",\"" << user.sn
				  << "\",\"" << user.mail
				  << "\",\""
				  << std::accumulate(user.proxy_addresses.begin(), user.proxy_addresses.end(), std::string(),
						  [](const std::string& a, const std::string& b) -> std::string {
							return a+(a.size()>0 ? ";" : "")+b;
						  })
				  << "\",\""
				  << "\",\"" << 0
				  << "\",\"" << 0
				  << "\",\"" << block.pattern
				  << "\",\"" << block.sender_count
				  << "\",\"" << block.hfrom_count
				  << "\"\r\n";
			}
		}
	}
}
std::size_t Proofpoint::UserList::GetSafeCount() const
{
	return std::accumulate(entries.begin(), entries.end(), 0, [](const std::size_t& a, const Entry& b) -> std::size_t {return a + b.safe_count;} );
}

std::size_t Proofpoint::UserList::GetBlockCount() const
{
	return std::accumulate(entries.begin(), entries.end(), 0, [](const std::size_t& a, const Entry& b) -> std::size_t {return a + b.block_count;} );
}
