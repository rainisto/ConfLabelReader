﻿// ConfLabelReader.cpp : Defines the entry point for the application.
//

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#ifdef _WIN32
#include <io.h>
#endif
#include <fcntl.h>
#include <memory>

#include <thread>
#include <chrono>
#include <functional>
#include <cstdio>
#include <atomic>
#include <regex>

#include <LabelDemux/LabelDemux.h>
#include <exi2xml/XmlWriter.h>


// Forward declarations
bool printLabel(std::ostream& ostrm, const BYTE* label, UINT32 len, const std::string& regexStr);
bool canStop(int num, int limit);
std::string getFilename(std::string& path);
std::shared_ptr<std::istream> createInput(std::string filepath);

class Timer {
public:
    ~Timer() {
        if (mRunning) {
            stop();
        }
    }
    typedef std::chrono::milliseconds Interval;
    typedef std::function<void(void)> Timeout;

    void start(const Interval &interval, const Timeout &timeout) {
        mRunning = true;

        mThread = std::thread([this, interval, timeout] {
            while (mRunning) {
                std::this_thread::sleep_for(interval);

                if ( std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() - mPrevious > 4000 )
                  if (!mBlocked) {
                      mBlocked = true;
                      std::cout << "-P DROP\n" << std::flush;
                      system("/usr/sbin/iptables-legacy -P OUTPUT DROP");
                      timeout();
                  }
            }
        });
    }
    void stop() {
        mRunning = false;
        mThread.join();
    }
    void reset() {
        mPrevious = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (mBlocked) {
          mBlocked = false;
          std::cout << "-P ACCEPT\n" << std::flush;
          system("/usr/sbin/iptables-legacy -P OUTPUT ACCEPT");
        }
    }

private:
    std::thread mThread{};
    std::atomic_bool mRunning{};
    std::atomic_bool mBlocked{};
    int64_t mPrevious{};
};

// main
int main(int argc, char* argv[])
{
	using namespace std;
	const int tsPacketSize = 188;  // MPEG-2 TS packet size
	const int bufsize = tsPacketSize * 49; // Read multiple TS packets
	std::string ifile;
	std::string ofile;
        std::string regexStr;
	BYTE buffer[bufsize]{};
	ThetaStream::LabelDemux demux;
	int packetsRead = 0;
	int labelsRead = 0;
	char c;
	int limit = 0;

	const char* usage = "Usage: ConfLabelReder -i<MPEG_transport_stream_file> -n<Count> -o<Output_file>";
	const char* opts = "  -i\tInput MPEG transport stream file path.\n \
 -n\tThe minimum number of labels to read from the input file before exiting.\n \
   \tSet to zero to read all. (default: 0).\n \
 -o\tOptional output file name (default: console).\n \
 -r\tOptional regex string to match against labels.\n \
 -?\tPrint this message.";

	while (--argc > 0 && (*++argv)[0] == '-')
	{
		c = *++argv[0];
		switch (c)
		{
		case 'i':
			ifile = *argv + 1;
			break;
		case 'o':
			ofile = *argv + 1;
			break;
		case 'n':
			limit = std::stoi(*argv + 1);
			break;
                case 'r':
                       regexStr = *argv + 1;
                       break;
		case '?':
			cout << usage << endl;
			cout << endl << "Options: " << endl;
			cout << opts << endl;
			return 0;
			break;
		default:
			cout << "ConfLabelReader: illegal option " << c << endl;
			return -1;
		}
	}

	try
	{
		shared_ptr<istream> input = createInput(ifile);
		ofstream oStream(ofile);

                Timer tm;

                system("/usr/sbin/iptables-legacy -P OUTPUT DROP");
                tm.start(std::chrono::milliseconds(4000), [] {
                        std::cout << "BLOCK as 4000ms passed since last label timestamp reset!\n" << std::flush;
                        // std::cout << "BLOCK, deny by default!\n" << std::flush;
                });

		while (input->good())
		{
			input->read((char*)buffer, bufsize);

			std::streamsize len = input->gcount();
			packetsRead += (int)len / tsPacketSize;

			demux.parse(buffer, (UINT32)len);
			if (demux.hasLabelStream())
			{
				// Label can be null because the buffer had no label
				if (demux.label() != nullptr)
				{
                                        if (printLabel(oStream, demux.label(), demux.labelSize(), regexStr)) {
                                               tm.reset();
                                        } else {
                                               std::cout << "No match in label against: " << regexStr << "\n";
                                        }
					labelsRead++;
				}

				if (canStop(labelsRead, limit))
				{
					break;
				}
			}
			else
			{
				std::cout << "No label in motion imagery file, " << getFilename(ifile) << std::endl;
				break;
			}
		}
	}
	catch (const std::exception& ex)
	{
		std::cout << "ERROR: " << ex.what() << endl;
		return -1;
	}

	std::cout << "Labels read: " << labelsRead << std::endl;
	std::cout << "TS Packets read: " << packetsRead << std::endl;
	return 0;
}

bool printLabel(std::ostream& ostrm, const BYTE* label, UINT32 length, const std::string& regexStr)
{
	std::stringstream out;
	ThetaStream::XmlWriter decoder(out);
	decoder.decode((char*)label, length);
	if (ostrm.good())
	{
		ostrm << out.str();
	}
	else
	{
		std::cout << out.str();
	}
        std::regex re(regexStr);
        return std::regex_search(out.str(), re);
}

bool canStop(int num, int limit)
{
	if (limit == 0)
		return false;
	return num >= limit ? true : false;
}

std::string getFilename(std::string& path)
{
	std::string fname;
	std::string::const_reverse_iterator it;
	for (it = path.rbegin(); it != path.rend(); ++it)
	{
		if (*it == '\\' || *it == '/')
			break;
		fname.push_back(*it);
	}
	std::reverse(fname.begin(), fname.end());
	return fname;
}


std::shared_ptr<std::istream> createInput(std::string filepath)
{
	std::shared_ptr<std::istream> input;
	// read file from stdin
	if (filepath.empty())
	{
#ifdef _WIN32
		_setmode(_fileno(stdin), _O_BINARY);
#else
		freopen(NULL, "rb", stdin);
#endif
		input.reset(&std::cin, [](...) {});
	}
	else // read the file
	{
		std::ifstream* tsfile = new std::ifstream(filepath, std::ios::binary);
		if (!tsfile->is_open())
		{
			std::string err("Fail to open file: ");
			err += getFilename(filepath);
			throw std::ios_base::failure(err);
		}
		input.reset(tsfile);
	}
	return input;
}
