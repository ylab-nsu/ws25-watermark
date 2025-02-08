# watermark
Watermark RISC-V

Питон приложение, позволяющее кодировать сообщения в elf файлах собранных под risc-v


Использует библиотеку capstone для работы, однако можно переписать программу без нее, будет работать только с модулем equal_funcs (единственный готовый
на момент презентации)

К концу зимней школы, имеется только один рабочий модуль, который опирается на замену инструкций на функционально эквивалентные, чтобы кодировать сообщение
в файл. Другой модуль (который скорее всего будет в моем форке), будет менять заданные компилятором размеры стек фреймов для кодирования, что, конечно 
будет минусом, поскольку будет уходить больше памяти (огромные количества в крайних случая), но в замен даст возможноть закодировать гораздо больше информации


Замены на функционально эквивалентные функции в контексте целой программы не вносят заметных изменений в скорость исполнения

![image](https://i.imgur.com/QVnxOlj.png)

## =============================
Python tool to encode messages in risc-v compiled elf files


Requires capstone library to work (although it is possible to make it work without Capstone, but only with one module)


By the time when coding camp ends we have only one module up and working, this module relies on functionaly equal assembler instructions
to encode message inside the binary (would be much easier to implement on CISC architecture), the other module (that most likely be imple
mented in my fork of this project) would tweak compiler's given sizes for stackframes in order to encode message, which, of course comes
with the tradeoff of memory (large amounts in some edge cases), but in turn should give much bigger amount of different combinations 
(e.g. unique binaries)
