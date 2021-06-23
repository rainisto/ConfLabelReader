#pragma once
#include "Pid2TypeMap.h"
#include "AccessUnit.h"

#include "libmp2t.h"

#include <string>

class LabelDemuxImpl :
	public lcss::TSParser
{
public:
	LabelDemuxImpl();
	~LabelDemuxImpl();

	virtual void parse(const BYTE* stream, unsigned long len);

	virtual void onPacket(lcss::TransportPacket& pckt);

	bool hasLabel() const;

	std::string label() const;

private:
	void processStartPayload(const lcss::TransportPacket& pckt);
	void processPayload(const lcss::TransportPacket& pckt);
	void processLabel();

private:
	lcss::ProgramAssociationTable _pat;
	lcss::ProgramMapTable _pmt;
	Pid2TypeMap _pmtHelper;
	AccessUnit _exiSample;
	bool _hasLabel;
	std::string _label;
};
