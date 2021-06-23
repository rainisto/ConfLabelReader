#pragma once
#include "labeldemux_export.h"

class LabelDemuxImpl;

typedef unsigned char BYTE;
typedef unsigned short UINT16;
typedef unsigned int UINT32;
typedef unsigned long long UINT64;

/// <summary>
/// LabelDemux reads sequence of bytes from a MPEG-2 Transport Stream and
/// extracts the STANAG 4774 Confidentiality Metadata Label from it if one
/// is available.  The client passes in the MPEG-2 Transport Stream in the 
/// parse() function and polls for the label by calling the label() function
/// after the parse() function returns.
/// </summary>
namespace ThetaStream
{
	class LABELDEMUX_EXPORT LabelDemux
	{
	public:
		LabelDemux();
		~LabelDemux();

		/// <summary>
		/// Parse the input btye stream and extract the Confidentiality Metadata
		/// Label.  Call the label() function after this function returns to 
		/// retrieve the Confidentiality Metadata Label.
		/// </summary>
		/// <param name="transport_stream">An array of bytes containing 
		/// MPEG-2 Transport Stream</param>
		/// <param name="len">The number of bytes of the transport_stream
		/// parameter.  It is recommended the len parameter should a multiple of 
		/// 188 bytes.  For example, len = 188 * 49.</param>
		void parse(const BYTE* transport_stream, unsigned long len);

		/// <summary>
		/// Call this function to determine if the stream passed into the parse()
		/// function contains a Confidentiality Metadata Label program element.
		/// </summary>
		/// <returns>Returns true if the transport stream passed into the parse()
		/// function contains a Confidentiality Metadata Label program
		/// element; otherwise, false.</returns>
		bool hasLabelStream() const;

		/// <summary>
		/// Retruns the Confidentiality Metadata Label in XML from the last parse()
		/// invocation.  Can be null if no label was found in the last parse() call.
		/// </summary>
		/// <returns>Returns XML label; otherwise, null.</returns>
		const char* label() const;

	private:
		LabelDemuxImpl* _pimpl;
		char* _label;
	};

}