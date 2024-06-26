#ifndef _FPRINTF_H_
#define _FPRINTF_H_

#undef GWIX412
#ifdef GWIX412
extern "C" {
extern int FPrintF(FILE* fp, const char* fmt, ...);
extern int PrintF (const char* fmt, ...);
}

#define fprintf FPrintF
#define printf  PrintF
#endif

#endif // _FPRINTF_H_
