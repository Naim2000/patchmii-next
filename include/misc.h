#define MAXIMUM(max, size) ( ( size > max ) ? max : size )
#define ALIGN(a,b) ((((a)+(b)-1)/(b))*(b))

extern void* memalign(size_t, size_t);
extern unsigned int sleep(unsigned int);
[[gnu::weak]] [[gnu::format (printf, 1, 2)]]
    extern void OSReport([[maybe_unused]] const char* fmt, ...) {}; // Dolphin lol

[[gnu::weak]] [[gnu::format (printf, 3, 4)]]
    extern void OSPanic(const char* file, int lineno, [[maybe_unused]] const char* fmt, ...) {};

#define debug_log(fmt, args...) OSReport("%s:%u : %s(): " fmt "\n", __FILE__, __LINE__, __func__, ##args)
#define error_log(fmt, args...) printf("%s(): " fmt "\n", __func__, ##args)
#define panic_log(fmt, args...) OSPanic(__FILE__, __LINE__, fmt, ##args)
