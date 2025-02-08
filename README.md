# watermark
Watermark RISC-V


Python tool to encode messages in risc-v compiled elf files


Requires capstone library to work (although it is possible to make it work without Capstone, but only with one module)


By the time when coding camp ends we have only one module is up and working, this module relies on functionaly equal assembler instructions
to encode message inside the binary (would be much easier to implement on CISC architecture), the other module (that most likely be imple
mented in my fork of this project) would tweak compiler's given sizes for stackframes in order to encode message, which, of course comes
with the tradeoff of memory (large amounts in some edge cases), but in turn should give much bigger amount of different combinations 
(e.g. unique binaries)
