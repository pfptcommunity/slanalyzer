/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */

#include "UserAnalyzer.h"
#include "CsvParser.h"
#include <chrono>
#include <iostream>
#include <iomanip>
#include "re2/re2.h"
#include "Utils.h"

void Proofpoint::UserAnalyzer::Load(const UserList& userlist, PatternErrors& pattern_errors)
{
	std::size_t count = 0;
	addr_to_user.reserve(userlist.GetAddressCount());
	for ( auto user = userlist.begin() ; user != userlist.end() ; user++ ) {
		std::size_t index = std::distance(userlist.begin(),user);
		addr_to_user.emplace(user->mail,index);
		for ( const auto& email : user->proxy_addresses ) {
			addr_to_user.emplace(email, index);
		}
		//safe_to_user.emplace(i,std::make_shared<Matcher>(true, false,RE2::ANCHOR_START));
		//for (std::size_t j = 0; j < userlist.entries[i].safe.size(); j++)
		//	safe_to_user[i]->Add(Utils::reverse_copy(userlist.entries[i].safe[j]), j, pattern_errors);

		//block_to_user.emplace(i,std::make_shared<Matcher>(true, false,RE2::ANCHOR_START));
		//for (std::size_t j = 0; j < userlist.entries[i].block.size(); j++)
		//	block_to_user[i]->Add(Utils::reverse_copy(userlist.entries[i].block[j]),j,pattern_errors);
		count++;
	}
}
std::size_t Proofpoint::UserAnalyzer::Process(const std::string& ss_file, UserList& userlist, std::size_t& records_processed)
{
	records_processed = 0;
	csv::HeaderIndex header_index;
	std::ifstream f(ss_file);
	csv::CsvParser parser(f);
	re2::StringPiece matches[2];
	RE2 hfrom_addr_only(R"(<?\s*([a-zA-Z0-9.!#$%&’*+\/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)\s*>?\s*(?:;|$))");
	RE2 inbound_check(R"(\bdefault_inbound\b)");
	csv::HeaderMap header_map;
	csv::HeaderList required_headers{"Policy_Route","Header_From","Sender","Recipients"};
	// Validate there are headers we are interested in...
	header_index = parser.FindHeader(required_headers, header_map);

	//std::cout << std::setw(35) << "Highest Index" << " " << std::setw(25) << header_index << std::endl;
	// std::multimap is useful for CSVs where there may be duplicate headers.
	//for (auto i = header_map.begin(); i!= header_map.end(); i++){
	//	std::cout << std::setw(35) << i->first << " " << std::setw(25) << i->second  << " " << header_map.count(i->first) << std::endl;
	//}
	if( header_index > -1 )
		for (auto& row : parser){
			bool inbound = RE2::PartialMatch(row[header_map.find("Policy_Route")->second], inbound_check);
			for( auto recipient : Utils::split(row[header_map.find("Recipients")->second],',') ){
				bool exists = addr_to_user.contains( std::string(recipient) );
			}
			/*
			bool h_from_match = hfrom_addr_only.Match(row[header_map.find("Header_From")->second], 0, row[header_map.find("Header_From")->second].length(), RE2::UNANCHORED, matches, 2);
			std::string header_from = (h_from_match) ? matches[1].ToString() : row[header_map.find("Header_From")->second];
			Utils::reverse(header_from);
			std::string sender = Utils::reverse_copy(row[header_map.find("Sender")->second]);

			addr_to_user
			for( auto s : safe_to_user )
			{
				//std::vector<std::size_t> matched_indexes;
				//bool b = false;
				//s.second->Match(header_from,matched_indexes);
				//userlist.entries[s.first]->safe_count++;
				//b |= s.second->Match(sender,matched_indexes);
			}
			for( auto b : block_to_user )
			{
				//std::vector<std::size_t> matched_indexes;
				//b.second->Match(header_from,matched_indexes);
				//b.second->Match(sender,matched_indexes);
				//userlist.entries[b.first]->block_count++;
			}
			//std::cout << count << std::endl;
			 */
			records_processed++;
		}
	return header_index;
}
