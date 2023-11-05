#define MAXIMUM(max, size) ( ( size > max ) ? max : size )
#define ALIGN(a,b) ((((a)+(b)-1)/(b))*(b))

extern void* memalign(size_t, size_t);
extern unsigned int sleep(unsigned int);
[[gnu::weak]] extern void OSReport([[maybe_unused]] const char* fmt, ...) [[gnu::format (printf, 1, 2)]]{}; // Dolphin lol
#define debug_log(fmt, args...) OSReport("%s:%u : %s(): " fmt "\n", __FILE__, __LINE__, __func__, ##args)
#define error_log(fmt, args...) printf("%s(): " fmt "\n", __func__, ##args)
