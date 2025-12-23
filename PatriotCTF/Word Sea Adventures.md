Forensics

The challenge is a docx file. A docx file is a zip archive.
Unzip the file using `unzip word_sea_adventures.docx -d word_sea_adventures`.

This extracts the contents of the docx file into a directory named `word_sea_adventures`.
Inside this directory, we find several files, including images and XML files.

The `document.xml` file contains a hint: "Word documents share a similar secret: although they appear as a single file, they are really like little 'zipped-up' bottles of fun." This confirms that we are on the right track by unzipping the file.

We then use the `steghide` tool to check for hidden data in the image files.
`steghide extract -sf word_sea_adventures/crab.jpg` extracts a file named `decoy2.txt`.
The content of `decoy2.txt` is "Mr Crabs heard that his cashier may be hiding some money and maybe a flag somewhere."

This hint points to the cashier of the Krusty Krab, who is Squidward.
We then use `steghide` on the `squid.jpg` file:
`steghide extract -sf word_sea_adventures/squid.jpg`

This extracts a file named `flag.txt`.
The content of `flag.txt` is:
I guess you found handsome squidward... even his looks can't hide the flag.
tctf{w0rD_f1le5_ar3_als0_z1p}

[[PatriotCTF-2025]]