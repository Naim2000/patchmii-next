#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <gccore.h>
#include <gctypes.h>
#include <ogc/isfs.h>
#include <network.h>
#include <wiiuse/wpad.h>
#include <runtimeiospatch.h>

typedef enum :u64{
	System = 0x00000001,
	DiscGame = 0x00010000,
	Channel = 0x00010001,
	SystemChannel = 0x00010002,
	DiscGameChannel = 0x00010004,
	HiddenChannel = 0x00010008,
} TitleType;

[[gnu::const]] u64 tid_full(TitleType hi, u32 lo) {
	return (hi << 32) | lo;
}

int PatchMii_Install(const u64, int, const u64, u32);

static void *xfb = NULL;
static GXRModeObj *rmode = NULL;

//---------------------------------------------------------------------------------
int main(int argc, char **argv) {
//---------------------------------------------------------------------------------
	int ret = 0;

	// Initialise the video system
	VIDEO_Init();

	// This function initialises the attached controllers
//	WPAD_Init();

	// Obtain the preferred video mode from the system
	// This will correspond to the settings in the Wii menu
	rmode = VIDEO_GetPreferredMode(NULL);

	// Allocate memory for the display in the uncached region
	xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));

	// Initialise the console, required for printf
	console_init(xfb,20,20,rmode->fbWidth,rmode->xfbHeight,rmode->fbWidth*VI_DISPLAY_PIX_SZ);

	// Set up the video registers with the chosen mode
	VIDEO_Configure(rmode);

	// Tell the video hardware where our display memory is
	VIDEO_SetNextFramebuffer(xfb);

	// Make the display visible
	VIDEO_SetBlack(FALSE);

	// Flush the video register changes to the hardware
	VIDEO_Flush();

	// Wait for Video setup to complete
	VIDEO_WaitVSync();
	if(rmode->viTVMode&VI_NON_INTERLACE) VIDEO_WaitVSync();

//	ISFS_Initialize();

	// The console understands VT terminal escape codes
	// This positions the cursor on row 2, column 0
	// we can use variables for this with format codes too
	// e.g. printf ("\x1b[%d;%dH", row, column );
	printf("\x1b[2;0H");
	printf("Hello World!\n");

	int dolphin_fd;
	IOS_Close((dolphin_fd = IOS_Open("/dev/dolphin", 0)));
	if (dolphin_fd < 0) {
		printf("applying IOS patches... ");
		ret = IosPatch_RUNTIME(true, false, true, false);
		if (ret < 0) {
			printf("failed!");
			while (!SYS_ResetButtonDown()) VIDEO_WaitVSync();
			exit(ret);
		}
		printf("ok!\n");
	}
	ISFS_Initialize();

	printf("Initializing network... ");
	for (int r = 0; r < 5; ++r) {
		ret = net_init();
		if (!ret || ret != -EAGAIN) break;
		sleep(1);
	}
	if (ret < 0) {
		printf("failed!");
		goto error;
	}
	printf("ok!\n");

	ret = PatchMii_Install(
			tid_full(HiddenChannel, 0x4843434A), -1, 0, 0);
	printf("PatchMii_Install returned %d", ret);

error:
	while (!SYS_ResetButtonDown())
		VIDEO_WaitVSync();

	return 0;
}
