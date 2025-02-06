from elftools.elf.elffile import ELFFile


class ElfWorker:
    def __init__(self, src_filename):
        self.src_filename = src_filename
        self.text_offset = 0
        self.text_size = 0

    def get_section_data(self, section_name, mode):
        with open(self.src_filename, mode) as f:
            elf = ELFFile(f)
            text = elf.get_section_by_name(section_name)
            self.text_offset = text["sh_addr"]
            self.text_size = text["sh_size"]
            return text.data()
