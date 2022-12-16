#pragma once

#define _RC(type, val) reinterpret_cast< type >(val)
#define _SC(type, val) static_cast< type >(val)

#define _SCU(val) static_cast< uint8_t* >(val)
#define _SCV(val) static_cast< void* >(val)
#define _SCC(val) static_cast< char* >(val)
#define _SCCC(val) static_cast< const char* >(val)
#define _SCCV(val) static_cast< const void* >(val)
#define _SCI(val) static_cast< int >(val)
#define _SCS(val) static_cast< size_t >(val)
#define _SCD(val) static_cast< double >(val)
