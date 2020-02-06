// DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.
//
// This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.
//
// © 2019 Massachusetts Institute of Technology.
//
// Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014)
//
// The software/firmware is provided to you on an As-Is basis
//
// Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.

#include "kvm_vm_serialization_tap.h"
#include <dirent.h>

/*
  This file contains functions for testing serialization and deserialization
  of kvm_vm_snapshot objects and kvm_vcpu_snapshot objects.
*/

static int unlink_cb(const char *fpath, __attribute__((unused))const struct stat *sb, __attribute__((unused))int typeflag, __attribute__((unused))struct FTW *ftwbuf)
{
    int rv = remove(fpath);

    if (rv)
        perror(fpath);

    return rv;
}

int rmrf(char *path)
{
    return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

// helper function for deserialization
// gets the name of every file in the provided directory path.
static char **
get_filenames_in_dir(const char *dir_path)
{
	DIR *  dir        = opendir(dir_path);
	char **filenames  = NULL;
	size_t file_count = 0;

	char **        foo      = NULL;
	struct dirent *file_itr = readdir(dir);
	while (file_itr) {
		// skip dotfiles, curr dir, and upper dir
		if (strstr(file_itr->d_name, ".") != file_itr->d_name) {
			// resize filenames chunk and copy over old pointers.
			// +1 for new pointer, +1 for null to signify end of array.
			foo = calloc(1, sizeof(char *) * ((file_count) + 2));
			// copy old pointers and free new chunk
			if (filenames) {
				memcpy(foo, filenames, sizeof(char *) * file_count);
				free(filenames);
			}
			filenames = foo;

			// copy the filename from the file_itr object.
			filenames[file_count] = calloc(1, strlen(file_itr->d_name) + 1);
			memcpy(filenames[file_count], file_itr->d_name, strlen(file_itr->d_name));
			file_count++;
		}
		file_itr = readdir(dir);
	}
	closedir(dir);

	return filenames;
}

static void
compare_kvm_vm_serializations(const char *serialized_vm1_dir, const char *serialized_vm2_dir)
{

	// array containing the names of every file in the specified directories
	char **vm1_filenames = get_filenames_in_dir(serialized_vm1_dir);
	char **vm2_filenames = get_filenames_in_dir(serialized_vm2_dir);

	u64 i = 0;
	// whether or not two serialized vm's are equal.
	bool missing_files = false;

	// check that for each file in vm1_dir, there is a file with a matching name in vm2_dir.
	while (vm1_filenames[i]) {
		u64  j          = 0;
		bool found_file = false;
		while (vm2_filenames[j]) {
			// if a file has been found with a matching filename, break.
			if (!strcmp(vm1_filenames[i], vm2_filenames[j])) {
				found_file = true;
				break;
			}
			j++;
		}
		// if we did not find a file in vm2_dir, we have missing files.
		if (!found_file) {
			missing_files = true;
			break;
		}
		i++;
	}

	// if vm2_dir is missing a file that vm1_dir has.
	if (missing_files) {
		ok(false, "reserialized vm is missing files!");
	} else {
		ok(true, "reserialized vm has matching files!");

		char *vm1_filepath = NULL;
		char *vm2_filepath = NULL;

		bool filesize_mismatch = false;
		bool content_mismatch  = false;
		i                      = 0;
		// check that file sizes match between the new serialized snapshot and the old one
		// for each file
		while (vm1_filenames[i]) {

			// path to file we are comparing
			asprintf(&vm1_filepath, "%s/%s", serialized_vm1_dir, vm1_filenames[i]);
			asprintf(&vm2_filepath, "%s/%s", serialized_vm2_dir, vm1_filenames[i]);

			FILE *vm1_file = fopen(vm1_filepath, "r");
			FILE *vm2_file = fopen(vm2_filepath, "r");

			// get size of file1
			fseek(vm1_file, 0, SEEK_END);
			size_t vm1_filesize = (size_t)ftell(vm1_file);
			rewind(vm1_file);

			// get size of file2
			fseek(vm2_file, 0, SEEK_END);
			size_t vm2_filesize = (size_t)ftell(vm2_file);
			rewind(vm2_file);

			if (vm1_filesize != vm2_filesize) {
				filesize_mismatch = true;
			} else {
				// compare contents of the two files, should be identical.
				char *vm1_filedata = calloc(1, vm1_filesize + 1);
				char *vm2_filedata = calloc(1, vm2_filesize + 1);
				// read contents.
				fread(vm1_filedata, vm1_filesize, 1, vm1_file);
				fread(vm2_filedata, vm2_filesize, 1, vm2_file);

				// check contents.
				if (memcmp(vm1_filedata, vm2_filedata, vm1_filesize) != 0) {
					content_mismatch = true;
				}
				free(vm1_filedata);
				free(vm2_filedata);
			}
			fclose(vm1_file);
			fclose(vm2_file);

			free(vm1_filepath);
			free(vm2_filepath);

			vm1_filepath = NULL;
			vm2_filepath = NULL;
			i++;
		}
		if (filesize_mismatch) {
			ok(false, "File size mismatch between serialized vm's!");
		} else {
			ok(true, "File sizes match for reserialized vm!");
		}

		if (content_mismatch) {
			ok(false, "Content mismatch in reserialized vm!");
		} else {
			ok(true, "Content match for serialized vm!");
		}
	}
	// free vm1_filenames
	i = 0;
	while (vm1_filenames[i]) {
		free(vm1_filenames[i]);
		i++;
	}
	free(vm1_filenames);

	// free vm2_filenames
	i = 0;
	while (vm2_filenames[i]) {
		free(vm2_filenames[i]);
		i++;
	}
	free(vm2_filenames);
}

// tests serialization, deserialization, and realization of kvm vms..
void
test_kvm_vm_serialization(const char *serialized_vm1_dir)
{
	diagnostics("Testing vm serialization and deserialization.");

	// deserialize flips presence bits off to hide substructs that are saved but not used.
	// we need to flip those flags back on to make our tests sound and complete.
	kvm_vm *new_vm = kvm_vm_deserialize(serialized_vm1_dir);
	diagnostics("Deserialized test vm, reserializing.");

	// serialize the newly deserialized snapshot.
    char *serialized_vm2_dir = kvm_vm_snapshot_serialize(new_vm, 0, true);

	diagnostics("Reserialization complete, comparing results.");
	compare_kvm_vm_serializations(serialized_vm1_dir, serialized_vm2_dir);
	diagnostics("done");
    rmrf(serialized_vm2_dir);
    free(serialized_vm2_dir);
	kvm_vm_free(new_vm);
	diagnostics("serialization/deserialization tests complete.");
}
