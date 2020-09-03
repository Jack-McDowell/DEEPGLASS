#pragma once

#include "LogSink.h"
#include "util/wrappers.hpp"

namespace Log {

	/**
	 * DebugSink provides a sink for the logger that directs output to the debug console.
	 *
	 * Each log message is prepended with the severity of the log, as defined in MessagePrepends.
	 */
	class DebugSink : public LogSink {
	private:

		/// A list of different prepends to be used at each log level
		static inline std::wstring MessagePrepends[4] = { L"[ERROR]", L"[WARNING]", L"[INFO]", L"[VERBOSE]" };

		/// A critical section ensuring associated messages occur consecutively
		CriticalSection hGuard;

	public:

		/**
		 * Outputs a message to the debug console if its logging level is enabled. The log message is prepended with 
		 * its severity level.
		 *
		 * @param level The level at which the message is being logged
		 * @param message The message to log
		 */
		virtual void LogMessage(
			IN CONST LogLevel& level,
			IN CONST std::wstring& message
		) override;

		/**
		 * Compares this Debug to another LogSink. Currently, as only one debug console is supported, any other
		 * DebugSink is considered to be equal. This is subject to change in the event that support for more debug
		 * consoles is added.
		 *
		 * @param sink The LogSink to compare
		 *
		 * @return Whether or not the argument and this sink are considered equal.
		 */
		virtual bool operator==(
			IN CONST LogSink& sink
		) const;
	};
}