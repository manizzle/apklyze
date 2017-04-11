import zipfile, os.path, sys, tempfile, argparse
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection

class ScanAndroidException(Exception):
	pass

class ScanAndroidExceptionBadFile(ScanAndroidException):
	pass

class ScanAndroidLib(object):
	''' Scan multiple ELF .so libraries to detect problems with their runtime dependencies
	as mandated by the following blog post: https://android-developers.googleblog.com/2016/06/android-changes-for-ndk-developers.html'''

	def __init__(self, libraries, extra=False):
		# This is a one-time dump of all known public Android libraries on API 24. Update when NDK API > 24
		# export D=$(ls /Users/manizzle/Library/Android/sdk/ndk-bundle/platforms/android-24/*/usr/lib/*.so | cut -d '/' -f 13 | sort -u | paste -d ',' -) && 
		# python -c "import os; print os.environ.get('D').splitlines()"
		self.public_libraries = set(['libEGL.so', 'libGLESv1_CM.so', 'libGLESv2.so', 'libGLESv3.so', 'libOpenMAXAL.so',
									'libOpenSLES.so', 'libandroid.so', 'libc.so', 'libcamera2ndk.so', 'libdl.so',
									'libjnigraphics.so', 'liblog.so', 'libm.so', 'libmediandk.so', 'libstdc++.so',
									'libvulkan.so', 'libz.so'])

		# THESE ARE LIBRARIES THAT WILL BE TEMPORARILY SUPPORTED!!!
		if extra:
			self.public_libraries |= set(['libandroid_runtime.so', 'libcutils.so', 'libcrypto.so', 'libssl.so'])

		# libraries are the file-like ELF binary objects that will have custom checks run over them
		self.libraries = libraries

		# this is important !! We need a list of libraries that exist within the application already
		# because libraries are allowed to link to libraries that have been copied into the current directory
		for name, _ in self.libraries:
			base_library = os.path.basename(name)
			if base_library:
				self.public_libraries.add(base_library)

		# list of checks that need to be run on the given binaries
		self.checks = [("Private APIs", self.private_api)]

		# Run analysis
		self.run()

	def run(self):
		for library_name, library in self.libraries:
			print >>sys.stderr, "\nLibrary: %s" % library_name
			try:
				self.run_checks(library)
			except ScanAndroidExceptionBadFile as e:
				print >>sys.stderr, "%s is not a well formed library" % library_name
				continue

	def run_checks(self, library):
		# Because the library is a file object, we want multiple checkers to run over the file
		# Create a temporary file that will contain the file contents and pass the temporary
		# file name to each checker. Because of the context handler, the file will be 
		# closed if a checker throws an exception
		with tempfile.NamedTemporaryFile() as tmpfile:
			tmpfile.write(library.read())
			tmpfile.flush()
			for check_name, check in self.checks:
				try:
					ret = check(tmpfile.name)
				except ScanAndroidExceptionBadFile as e:
					# If any checker throws a BadFile exception, no reason to run other checkers
					raise
				except ScanAndroidException as e:
					# This exception might be checker specific, so run other checkers
					continue
				print >>sys.stderr, "Binary Check: %s" % check_name
				if ret:
					print >>sys.stderr, ret

	def private_api(self, library):
		# Loads an ELF executable, and find all requested libraries (DT_NEEDED)
		# that should not be requested as they are not public
		# or copied in to the current directory
		ret = []
		with open(library, "rb") as f:
			try:
				elffile = ELFFile(f)
			except Exception as e:
				raise ScanAndroidExceptionBadFile
			for section in elffile.iter_sections():
				if isinstance(section, DynamicSection):
					for tag in section.iter_tags():
						if tag.entry.d_tag == "DT_NEEDED":
							if tag.needed not in self.public_libraries:
								ret.append(tag.needed)
		return "Illegal imported libraries: " + ", ".join(ret)

class ApkLoaderException(Exception):
	pass

class ApkLoader(object):
	''' Load an Android application and do light analysis to allow for future analysis'''
	def __init__(self, apk):
		try:
			self.apk = zipfile.ZipFile(apk)
		except (zipfile.BadZipfile) as e:
			raise ApkLoaderException("Zipfile failed to parse " + apk)

	def get_native_libraries(self):
		libraries = []
		for entry in self.apk.infolist():
			if entry.filename.endswith(".so") and entry.filename.startswith("lib/"):
				try:
					libraries.append((entry.filename, self.apk.open(entry)))
				except RuntimeError as e:
					raise ApkLoaderException("Could not open " + entry.filename)
		return libraries

	def close(self):
		self.apk.close()

def main():
	parser = argparse.ArgumentParser(description="APKLyze: Find problems with your APK")
	parser.add_argument("apk", help="The filename of the target APK")
	parser.add_argument("--extra", default=False, action="store_true", help="For the Private Library check, allow APKs to allow extra libraries", required=False)
	args = parser.parse_args()
	apk_obj = ApkLoader(args.apk)
	apk_libraries = apk_obj.get_native_libraries()
	apk_scanner = ScanAndroidLib(apk_libraries, args.extra)
	apk_obj.close()

if __name__ == "__main__":
	main()



