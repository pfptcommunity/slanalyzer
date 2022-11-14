/**
 * This code was tested against C++20
 *
 * @author Ludvik Jerabek
 * @package slanalyzer
 * @version 1.0.0
 * @license MIT
 */
#include "src/Analyzer.h"
#include <getopt.h>
#include <filesystem>
#include <chrono>
#include <iostream>

using namespace std;
using namespace std::chrono;

void help()
{
	cout << "Usage: slanalyzer [-h] [-s SAFELIST|BLOCKLIST] [-o OUTPUTFILE] [SS_FILES...]"
		 << endl
		 << endl
		 << "Search multiple smart search exports to determine which safe or block list entries triggered against the mail flow."
		 << endl
		 << endl
		 << "Options:"
		 << endl
		 << "-s, --safelist        (required) safelist file to use for smart search file processing"
		 << endl
		 << "-o, --output          (required) annotated safelist created after smart search processing"
		 << endl
		 << "-h, --help            show this help message and exit"
		 << endl
		 << endl
		 << "Positional Arguments:"
		 << endl
		 << "SS_FILES              (required positional) one or more cloud smart search exports."
		 << endl
		 << endl;
}

void usage()
{
	cout << "Usage: slanalyzer [-h] [-s SAFELIST|BLOCKLIST] [-o OUTPUTFILE] [SMART_SEARCH_FILES...]" << endl
		 << "Try 'slanalyzer --help' for more information." << endl;
}

int main(int argc, char* argv[])
{
	if (argc==1) {
		usage();
		exit(1);
	}

	int c;
	string input_list;
	string output_list;
	vector<string> ss_inputs;
	bool input = false;
	bool output = false;
	bool files = false;
	static struct option long_options[] =
			{
					{("safelist"), required_argument, 0, 's'},
					{("output"), required_argument, 0, 'o'},
					{("help"), no_argument, 0, 'h'},
					{0, 0, 0, 0}
			};

	int option_index = 0;

	while ((c = getopt_long(argc, argv, "s:o:h", long_options, &option_index))!=-1) {
		switch (c) {
		case 's': input_list = optarg;
			input = true;
			break;
		case 'o': output_list = optarg;
			output = true;
			break;
		case 'h': help();
			exit(0);
			break;
		case '?':
		default: usage();
			exit(1);
			break;
		}
	}

	if (optind<argc) {
		files = true;
		while (optind<argc) {
			if (!filesystem::exists(argv[optind])) {
				cerr << "Smart search file " << quoted(argv[optind]) << " doesn't exist." << endl;
				exit(1);
			}
			ss_inputs.emplace_back(argv[optind]);
			optind++;
		}
	}

	if (input && input_list.empty()) {
		cerr << "Input list can not be an empty string." << endl;
		exit(1);
	}

	if (input && !filesystem::exists(input_list)) {
		cerr << "Input list: " << quoted(input_list) << " doesn't exist" << endl;
		exit(1);
	}

	if (output && output_list.empty()) {
		cerr << "Output file can not be an empty string." << endl;
		exit(1);
	}

	filesystem::path p(output_list);
	if (filesystem::is_directory(p)) {
		cerr << "Output file is a directory: " << quoted(output_list)
			 << " please specify a filename" << endl;
		exit(1);
	}

	if (ss_inputs.empty()) {
		cerr << "Smart search files must be provided." << endl;
		exit(1);
	}

	if (!input || !output || !files) {
		usage();
		exit(1);
	}

	auto start = high_resolution_clock::now();
	Proofpoint::SafeList safelist;
	safelist.Load(input_list);

	// Used to collect pattern errors in the even there is a bad pattern
	Proofpoint::PatternErrors errors;

	Proofpoint::Analyzer processor(safelist, errors);

	for (const auto& file : ss_inputs) {
		processor.Process(file, safelist);
	}

	safelist.Save(output_list);

	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop-start);
	cout << right << setw(25) << "Completed: "
		 << left << setw(25) << to_string(duration.count())+"μs"
		 << setw(10) << setprecision(2) << "["+to_string((double)duration.count()/1000000)+"s]"
		 << endl;

	if (!errors.empty()) {
		cout << "Pattern errors occurred, see the following entries in your safe or blocked list:" << endl;
		for (auto e : errors) {
			cout << "Line: " << e.index << " Pattern: " << e.pattern << " Reason: " << e.error << endl;
		}
	}

	return 0;
}
