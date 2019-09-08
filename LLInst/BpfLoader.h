#ifndef BPFLOADER_H
#define BPFLOADER_H

#include <elf.h>

#include <string>
#include <exception>
#include <vector>
#include <map>

class bpf_loader_exception: public std::exception {
  const char *msg;
public:
  explicit bpf_loader_exception(const char *_msg): msg(_msg) {}
  const char *what() const noexcept { return msg; }
};

struct BpfSection
{
  BpfSection(const char *_name, Elf64_Shdr *_hdr): BpfSection(_name, NULL, 0, _hdr) {}
  BpfSection(const char *_name, size_t _size, Elf64_Shdr *_hdr): BpfSection(_name, (unsigned char *)calloc(_size, 1), _size, _hdr) {}
  BpfSection(const char *_name, unsigned char *_start, size_t _length, Elf64_Shdr *_hdr): name(_name), start(_start), length(_length), hdr(_hdr) {}
  const std::string name;
  unsigned char *start;
  size_t length;
  Elf64_Shdr *hdr;

  bool isBss() const { return hdr->sh_type == SHT_NOBITS; }
  bool isData() const { return hdr->sh_type == SHT_PROGBITS; }
};

struct EBpfInstruction {
  union {
    struct {
      uint8_t opcode;
      uint8_t dst:4;
      uint8_t src:4;
       int16_t offset;
       int32_t imm;
    };
    uint64_t raw;
  };
  void *source;
  Elf64_Sym *rel;
};

typedef std::vector<EBpfInstruction> BpfProg;

class BpfLoader
{
  BpfLoader(const char *fileName);
public:
  BpfLoader(const std::map<std::string, uint64_t> &cbs,std::string fileName);
  const std::vector<BpfSection> &getSections() const { return sections; }
  const std::map<Elf64_Sym*, std::string> &referencedSymbols() const { return symbols; }
  const std::map<std::string, BpfProg> &exportedFunctions() const { return functions; }
  ~BpfLoader();
private:
  size_t length = 0;
  unsigned char *mappedFile;
  std::map<std::string, uint64_t> callbacks;
  std::vector<BpfSection> sections;
  std::map<Elf64_Sym*, std::string> symbols;
  Elf64_Sym *symtab = NULL;
  size_t symtabEntryCount = 0;
  const char *strtab = NULL;
  std::map<std::string, BpfProg> functions;

  void parse();
  void parseSections(Elf64_Ehdr *header);
  void processRelocations();
  void fetchFunctions();
  EBpfInstruction *insnFrom(void *ptr);
};

#endif // BPFLOADER_H
