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

#define ADBG_EXPECT(c, Expected, Got) \
	ADBG_EXPECT_ENUM(c, Expected, Got)

#define ADBG_EXPECT_NOT(c, Expected, Got) \
	ADBG_EXPECT_NOT_ENUM(c, Expected, Got)

#define ADBG_EXPECT_ENUM(c, Expected, Got) \
	Do_ADBG_Expect(c, __FILE__, __LINE__, Expected, Got, #Got)

#define ADBG_EXPECT_NOT_ENUM(c, NotExpected, Got) \
	Do_ADBG_ExpectNot(c, __FILE__, __LINE__,  NotExpected, Got, #Got)

#define ADBG_EXPECT_BOOLEAN(c, Expected, Got) \
	ADBG_EXPECT_ENUM(c, Expected, Got)

#define ADBG_EXPECT_TRUE(c, Got) \
	ADBG_EXPECT_ENUM(c, true, Got)

#define ADBG_EXPECT_EQUAL(c, Buf1_p, Buf2_p, Length) \
	ADBG_EXPECT(c, 0, memcmp(Buf1_p, Buf2_p, Length))

#define ADBG_EXPECT_BUFFER(c, ExpBuf_p, ExpBufLen, GotBuf_p, GotBufLen) \
	Do_ADBG_ExpectBuffer(c, __FILE__, __LINE__, \
			     ExpBuf_p, ExpBufLen, #GotBuf_p, GotBuf_p, \
			     #GotBufLen, GotBufLen)

#define ADBG_EXPECT_POINTER(c, Expected, Got) \
	Do_ADBG_ExpectPointer(c, __FILE__, __LINE__, Expected, Got, #Got)

#define ADBG_EXPECT_NOT_NULL(c, Got) \
	Do_ADBG_ExpectPointerNotNULL(__FILE__, __LINE__, Got, #Got)

#define ADBG_EXPECT_COMPARE_SIGNED(c, Val1, Compar, Val2) \
	Do_ADBG_ExpectCompareSigned(c, __FILE__, __LINE__, \
				    Val1, Val2, (Val1)Compar( \
					    Val2), #Val1, #Compar, #Val2)

#define ADBG_EXPECT_COMPARE_UNSIGNED(c, Val1, Compar, Val2) \
	Do_ADBG_ExpectCompareUnsigned(c, __FILE__, __LINE__, \
				      Val1, Val2, (Val1)Compar( \
					      Val2), #Val1, #Compar, #Val2)

#define ADBG_EXPECT_COMPARE_POINTER(c, Val1, Compar, Val2) \
	Do_ADBG_ExpectComparePointer(c, __FILE__, __LINE__, \
				     Val1, Val2, (Val1)Compar( \
					     Val2), #Val1, #Compar, #Val2)


#define ADBG_EXPECT_TEEC_RESULT(c, exp, got) \
	ADBG_EXPECT_ENUM(c, exp, got)

#define ADBG_EXPECT_TEEC_SUCCESS(c, got) \
	ADBG_EXPECT_ENUM(c, TEEC_SUCCESS, got)

struct ADBG_Case {
	const char *header;
	bool success;
};

void ADBG_Assert(struct ADBG_Case *c);

bool Do_ADBG_Expect(struct ADBG_Case *c, const char *const FileName_p,
		    const int LineNumber, const int Expected, const int Got,
		    const char *const GotVarName_p);

bool Do_ADBG_ExpectNot(struct ADBG_Case *c, const char *const FileName_p,
		       const int LineNumber, const int NotExpected,
		       const int Got, const char *const GotVarName_p);

bool Do_ADBG_ExpectBuffer(struct ADBG_Case *c, const char *const FileName_p, const int LineNumber,
			  const void *const ExpectedBuffer_p,
			  const size_t ExpectedBufferLength,
			  const char *const GotBufferName_p,
			  const void *const GotBuffer_p,
			  const char *const GotBufferLengthName_p,
			  const size_t GotBufferLength);

bool Do_ADBG_ExpectPointer(struct ADBG_Case *c, const char *const FileName_p, const int LineNumber,
			   const void *Expected_p, const void *Got_p,
			   const char *const GotVarName_p);

bool Do_ADBG_ExpectPointerNotNULL(struct ADBG_Case *c, const char *const FileName_p,
				  const int LineNumber, const void *Got_p,
				  const char *const GotVarName_p);

bool Do_ADBG_ExpectCompareSigned(struct ADBG_Case *c, const char *const FileName_p,
				 const int LineNumber, const long Value1,
				 const long Value2, const bool Result,
				 const char *const Value1Str_p,
				 const char *const ComparStr_p,
				 const char *const Value2Str_p);

bool Do_ADBG_ExpectCompareUnsigned(struct ADBG_Case *c, const char *const FileName_p,
				   const int LineNumber,
				   const unsigned long Value1,
				   const unsigned long Value2,
				   const bool Result,
				   const char *const Value1Str_p,
				   const char *const ComparStr_p,
				   const char *const Value2Str_p);

bool Do_ADBG_ExpectComparePointer(struct ADBG_Case *c, const char *const FileName_p,
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
