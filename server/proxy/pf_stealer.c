/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * FreeRDP Clipboard Files Stealer
 *
 * Copyright 2019 Kobi Mizrachi <kmizrachi18@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <winpr/wtypes.h>
#include <winpr/file.h>
#include <winpr/collections.h>
#include <freerdp/log.h>

#include "pf_stealer.h"

void pf_stealer_set_files(pfClipboard* clipboard, FILEDESCRIPTOR* descriptors, UINT count)
{
    if (clipboard->descriptors)
        free(clipboard->descriptors);

    if (clipboard->stolen_files)
        free(clipboard->stolen_files);

    clipboard->descriptors = descriptors;
    clipboard->descriptors_count = count;

    // TODO realloc instead of free & calloc
    clipboard->stolen_files = calloc(count, sizeof(stolenFile));
    if (!clipboard->stolen_files)
        return;
}

BOOL pf_stealer_write_file(pfClipboard* clipboard, UINT32 listIndex, const BYTE* data, UINT32 len)
{
    stolenFile* file;
    FILEDESCRIPTOR descriptor;
    UINT32 written;
    
    if (listIndex >= clipboard->descriptors_count)
        return FALSE;

    file = &clipboard->stolen_files[listIndex];
    descriptor = clipboard->descriptors[listIndex];
    
    if (file->handle == NULL)
    {
        printf("opening file\n");
        /* open file */
		file->handle = CreateFileW(descriptor.cFileName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
		                    descriptor.dwFileAttributes, NULL);

		if (!file->handle || file->handle == INVALID_HANDLE_VALUE)
            return ERROR_INTERNAL_ERROR;
    }
    
    
    /* seek to end of file */
    SetFilePointer(file->handle, 0l, NULL, FILE_END);

    /* append data to file */
    if (!WriteFile(file->handle, data, len, &written, NULL))
    {
        WLog_ERR("clipboard", "WriteFile failed!");
        CloseHandle(file->handle);
        file->handle = NULL;
        return FALSE;
    }

    file->written += written;

    printf("written: %d, file size: %d\n", file->written, descriptor.nFileSizeLow);
    // TODO support large files
    if (file->written == descriptor.nFileSizeLow)
    {
        printf("finished writing file, closing.\n");
        /* close file handle */
        CloseHandle(file->handle);
    }

    return TRUE;
}

pfClipboard* pf_stealer_new(void)
{
    pfClipboard* pfc;

    pfc = (pfClipboard*) calloc(1, sizeof(pfClipboard));
    if (!pfc)
        return NULL;

    return pfc;
}
