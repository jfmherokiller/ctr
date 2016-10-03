#include <stdint.h>

#define MAGIC_CRO0 0x304f5243
#define MAGIC_FIXD 0x44584946

typedef struct {
    uint32_t base;
    uint32_t sz;
    uint32_t id;
} cro_segment;

typedef struct {
    uint32_t name_off;
    uint32_t data_off;
} cro_export;

typedef struct {
    uint32_t name_off;
    uint32_t symbol_off;
} cro_import;

typedef struct {
    uint32_t out_off;
    uint8_t  type;
    uint8_t  is_last;
    uint8_t  unk0; // ??
    uint8_t  unk1; // ??
    uint32_t x;
} cro_patch;

typedef struct {
    uint8_t  hashtbl[0x80];
    uint32_t magic;
    uint32_t code_size;
    uint32_t unknown0[2];
    uint32_t file_size;
    uint32_t unknown1[6];
    uint32_t base_addr; // ??

    uint32_t code_off;
    uint32_t code_sz;
    uint32_t unk1_off; // ??
    uint32_t unk1_num;
    uint32_t name_off;
    uint32_t name_sz;
    uint32_t seg_tbl_off;
    uint32_t seg_tbl_num;
    uint32_t exp_tbl_off;
    uint32_t exp_tbl_num;
    uint32_t unk3_off; // ??
    uint32_t unk3_num;
    uint32_t exp_str_off;
    uint32_t exp_str_sz;
    uint32_t exp_tree_off;
    uint32_t exp_tree_sz;
    uint32_t unk4_off; // ??
    uint32_t unk4_num;
    uint32_t imp_patches_off; // ??
    uint32_t imp_patches_num;
    uint32_t imp1_tbl_off;
    uint32_t imp1_tbl_num;
    uint32_t imp2_tbl_off;
    uint32_t imp2_tbl_num;
    uint32_t imp3_tbl_off;
    uint32_t imp3_tbl_num;
    uint32_t imp_str_off;
    uint32_t imp_str_sz;
    uint32_t unk8_off; // ??
    uint32_t unk8_num;
    uint32_t patches_off;
    uint32_t patches_num;
    uint32_t unk9_off; // ??
    uint32_t unk9_num;
    uint32_t padding[0x12];
} cro_header;

void cro_process(FILE* fd, size_t len);
