/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef ADBG_H
#define ADBG_H
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
//#include <sys/queue.h>

#define ADBG_STRING_LENGTH_MAX (1024)

/*
 * Expect functions/macros
 */

#define ADBG_EXPECT(Expected, Got) \
	ADBG_EXPECT_ENUM(Expected, Got)

#define ADBG_EXPECT_NOT(Expected, Got) \
	ADBG_EXPECT_NOT_ENUM(Expected, Got)

#define ADBG_EXPECT_ENUM(Expected, Got) \
	Do_ADBG_Expect(__FILE__, __LINE__, Expected, Got, #Got)

#define ADBG_EXPECT_NOT_ENUM(NotExpected, Got, EnumTable_p) \
	Do_ADBG_ExpectNot(__FILE__, __LINE__,  NotExpected, Got, #Got)

#define ADBG_EXPECT_BOOLEAN(Expected, Got) \
	ADBG_EXPECT_ENUM(Expected, Got)

#define ADBG_EXPECT_TRUE(Got) \
	ADBG_EXPECT_ENUM(true, Got)

#define ADBG_EXPECT_EQUAL(Buf1_p, Buf2_p, Length) \
	ADBG_EXPECT(0, memcmp(Buf1_p, Buf2_p, Length))

#define ADBG_EXPECT_BUFFER(ExpBuf_p, ExpBufLen, GotBuf_p, GotBufLen) \
	Do_ADBG_ExpectBuffer(__FILE__, __LINE__, \
			     ExpBuf_p, ExpBufLen, #GotBuf_p, GotBuf_p, \
			     #GotBufLen, GotBufLen)

#define ADBG_EXPECT_POINTER(Expected, Got) \
	Do_ADBG_ExpectPointer(__FILE__, __LINE__, Expected, Got, #Got)

#define ADBG_EXPECT_NOT_NULL(Got) \
	Do_ADBG_ExpectPointerNotNULL(__FILE__, __LINE__, Got, #Got)

#define ADBG_EXPECT_COMPARE_SIGNED(Val1, Compar, Val2) \
	Do_ADBG_ExpectCompareSigned(__FILE__, __LINE__, \
				    Val1, Val2, (Val1)Compar( \
					    Val2), #Val1, #Compar, #Val2)

#define ADBG_EXPECT_COMPARE_UNSIGNED(Val1, Compar, Val2) \
	Do_ADBG_ExpectCompareUnsigned(__FILE__, __LINE__, \
				      Val1, Val2, (Val1)Compar( \
					      Val2), #Val1, #Compar, #Val2)

#define ADBG_EXPECT_COMPARE_POINTER(Val1, Compar, Val2) \
	Do_ADBG_ExpectComparePointer(__FILE__, __LINE__, \
				     Val1, Val2, (Val1)Compar( \
					     Val2), #Val1, #Compar, #Val2)


#define ADBG_EXPECT_TEEC_RESULT(c, exp, got) \
	ADBG_EXPECT_ENUM(exp, got)

#define ADBG_EXPECT_TEEC_SUCCESS(c, got) \
	ADBG_EXPECT_ENUM(TEEC_SUCCESS, got)

bool Do_ADBG_Expect(const char *const FileName_p,
		    const int LineNumber, const int Expected, const int Got,
		    const char *const GotVarName_p);

bool Do_ADBG_ExpectNot(const char *const FileName_p,
		       const int LineNumber, const int NotExpected,
		       const int Got, const char *const GotVarName_p);

bool Do_ADBG_ExpectBuffer(const char *const FileName_p, const int LineNumber,
			  const void *const ExpectedBuffer_p,
			  const size_t ExpectedBufferLength,
			  const char *const GotBufferName_p,
			  const void *const GotBuffer_p,
			  const char *const GotBufferLengthName_p,
			  const size_t GotBufferLength);

bool Do_ADBG_ExpectPointer(const char *const FileName_p, const int LineNumber,
			   const void *Expected_p, const void *Got_p,
			   const char *const GotVarName_p);

bool Do_ADBG_ExpectPointerNotNULL(const char *const FileName_p,
				  const int LineNumber, const void *Got_p,
				  const char *const GotVarName_p);

bool Do_ADBG_ExpectCompareSigned(const char *const FileName_p,
				 const int LineNumber, const long Value1,
				 const long Value2, const bool Result,
				 const char *const Value1Str_p,
				 const char *const ComparStr_p,
				 const char *const Value2Str_p);

bool Do_ADBG_ExpectCompareUnsigned(const char *const FileName_p,
				   const int LineNumber,
				   const unsigned long Value1,
				   const unsigned long Value2,
				   const bool Result,
				   const char *const Value1Str_p,
				   const char *const ComparStr_p,
				   const char *const Value2Str_p);

bool Do_ADBG_ExpectComparePointer(const char *const FileName_p,
				  const int LineNumber,
				  const void *const Value1_p,
				  const void *const Value2_p, const bool Result,
				  const char *const Value1Str_p,
				  const char *const ComparStr_p,
				  const char *const Value2Str_p);

/**
 * Writes a string to output.
 * String length max is defined by ADBG_STRING_LENGTH_MAX
 *
 * @param Format_p The formatting string as in printf
 */
//void Do_ADBG_Log(const char *const Format_p, ...)
//__attribute__((__format__(__printf__, 1, 2)));

/**
 * Writes out the contents of buf_p formatted so that each line will
 * have cols number of columns.
 *
 * @param[in] Buf_p  Buffer to print
 * @param[in] Size   Size of buffer (in bytes)
 * @param[in] Cols   Number of columns.
 */
void Do_ADBG_HexLog(const void *const Buf_p, const size_t Size,
		    const size_t Cols);

#endif /* ADBG_H */
