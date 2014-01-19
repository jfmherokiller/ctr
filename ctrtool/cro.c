#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "cro.h"

static const char* cro_patchout = NULL;
static const char* cro_binout = NULL;

void cro_set_symbolout(const char* c) {
    cro_patchout = c;
}

void cro_set_binout(const char* c) {
    cro_binout = c;
}

const char* cro_segment_from_id(uint32_t id) {
    if(id == 0)
        return ".text";
    else if(id == 1)
        return ".data";
    else if(id == 2) // which is data and bss?
        return ".unk1";
    else if(id == 3)
        return ".unk2";
    return ".unknown";
}

uint32_t cro_decode_seg_offset(cro_segment* seg_tbl, uint32_t seg_tbl_num, uint32_t off) {
    uint32_t seg_idx = off & 0xf;

    if(seg_idx >= seg_tbl_num) {
        printf("ERROR: invalid segment referenced in offset.\n");
        return -1;
    }

    return seg_tbl[seg_idx].base + (off >> 4);
}

void cro_process(FILE* fd, size_t len) {
    uint8_t* cro = malloc(len);

    if(cro == NULL) {
        perror("malloc");
        return;
    }

    if(fread(cro, len, 1, fd) != 1) {
        perror("fread");
        free(cro);
        return;
    }

    cro_header h;
    memcpy(&h, cro, sizeof(h));

    if(h.magic != MAGIC_CRO0 && h.magic != MAGIC_FIXD) {
        fprintf(stderr, "Invalid magic\n");
        free(cro);
        return;
    }

    // Dump header.
    printf("\nHeader:\n");
    printf("Code size:\t\t0x%"PRIx32"\n", h.code_size);
    printf("Unknown field:\t\t0x%"PRIx32"\n", h.unknown0[0]);
    printf("Unknown field:\t\t0x%"PRIx32"\n", h.unknown0[1]);
    printf("File size:\t\t0x%"PRIx32"\n", h.file_size);
    printf("Unknown field:\t\t0x%"PRIx32"\n", h.unknown1[0]);
    printf("Unknown field:\t\t0x%"PRIx32"\n", h.unknown1[1]);
    printf("Unknown field:\t\t0x%"PRIx32"\n", h.unknown1[2]);
    printf("Unknown field:\t\t0x%"PRIx32"\n", h.unknown1[3]);
    printf("Unknown field:\t\t0x%"PRIx32"\n", h.unknown1[4]);
    printf("Unknown field:\t\t0x%"PRIx32"\n", h.unknown1[5]);
    printf("Base address:\t\t0x%"PRIx32"\n", h.base_addr);
    printf("Code offset:\t\t%"PRIx32"\n", h.code_off);
    printf("Code size:\t\t0x%"PRIx32"\n", h.code_sz);
    printf("unk1 offset:\t\t0x%"PRIx32"\n", h.unk1_off);
    printf("unk1 num:\t\t0x%"PRIx32"\n", h.unk1_num);
    printf("Name offset:\t\t0x%"PRIx32"\n", h.name_off);
    printf("Name size:\t\t0x%"PRIx32"\n", h.name_sz);
    printf("Segment Table offset:\t0x%"PRIx32"\n", h.seg_tbl_off);
    printf("Segment Table num:\t%"PRId32"\n", h.seg_tbl_num);
    printf("Export Table offset:\t0x%"PRIx32"\n", h.exp_tbl_off);
    printf("Export Table num:\t%"PRId32"\n", h.exp_tbl_num);
    printf("unk3 offset:\t\t0x%"PRIx32"\n", h.unk3_off);
    printf("unk3 num:\t\t%"PRId32"\n", h.unk3_num);
    printf("Export Strings offset:\t0x%"PRIx32"\n", h.exp_str_off);
    printf("Export Strings size:\t0x%"PRIx32"\n", h.exp_str_sz);
    printf("Export Tree offset:\t0x%"PRIx32"\n", h.exp_tree_off);
    printf("Export Tree num:\t%"PRId32"\n", h.exp_tree_sz);
    printf("unk4 offset:\t\t0x%"PRIx32"\n", h.unk4_off);
    printf("unk4 num:\t\t%"PRId32"\n", h.unk4_num);
    printf("Import Patches offset:\t0x%"PRIx32"\n", h.imp_patches_off);
    printf("Import Patches num:\t%"PRId32"\n", h.imp_patches_num);
    printf("Import Table 1 offset:\t0x%"PRIx32"\n", h.imp1_tbl_off);
    printf("Import Table 1 num:\t%"PRId32"\n", h.imp1_tbl_num);
    printf("Import Table 2 offset:\t0x%"PRIx32"\n", h.imp2_tbl_off);
    printf("Import Table 2 num:\t%"PRId32"\n", h.imp2_tbl_num);
    printf("Import Table 3 offset:\t0x%"PRIx32"\n", h.imp3_tbl_off);
    printf("Import Table 3 num:\t%"PRId32"\n", h.imp3_tbl_num);
    printf("Import Strings offset:\t0x%"PRIx32"\n", h.imp_str_off);
    printf("Import Strings size:\t0x%"PRIx32"\n", h.imp_str_sz);
    printf("unk8 offset:\t\t0x%"PRIx32"\n", h.unk8_off);
    printf("unk8 num:\t\t%"PRId32"\n", h.unk8_num);
    printf("Import Info offset:\t0x%"PRIx32"\n", h.imp_info_off);
    printf("Import Info num:\t%"PRId32"\n", h.imp_info_num);
    printf("unk9 offset:\t\t0x%"PRIx32"\n", h.unk9_off);
    printf("unk9 num:\t\t%"PRId32"\n", h.unk9_num);

    FILE* sym_fd = NULL;

    // Extract exported symbols.
    if(cro_patchout) {
        printf("Writing symbols to %s..\n", cro_patchout);

        sym_fd = fopen(cro_patchout, "w");
        if(sym_fd == NULL)
            perror("fopen");
        else {
            fprintf(sym_fd, "#include <idc.idc>\n");
            fprintf(sym_fd, "static main() {\n");
            fprintf(sym_fd, "DeleteAll();\n");
        }
    }

    // Dump Segment Table.
    if(!h.seg_tbl_num) {
        printf("ERROR: No segments..\n");
        free(cro);
        return;
    }

    cro_segment* s = (cro_segment*) (cro + h.seg_tbl_off);

    printf("\nSegment Table:\n");
    uint32_t i;
    for(i=0; i<h.seg_tbl_num; i++) {
        printf("\tSegment %"PRIx32"\n", i);
        printf("\t\tSegment base:\t\t0x%"PRIx32"\n", s[i].base);
        printf("\t\tSegment size:\t\t0x%"PRIx32"\n", s[i].sz);
        printf("\t\tSegment id:\t\t%"PRId32"\t(%s)\n", s[i].id,
               cro_segment_from_id(s[i].id));

        if(s[i].sz && sym_fd != NULL) {
            fprintf(sym_fd, "AddSeg(0x%"PRIx32", 0x%"PRIx32", 0, 1, saRelDble, scPub);\n",
                    s[i].base, s[i].base + s[i].sz);
            fprintf(sym_fd, "SetSegmentType(0x%"PRIx32", 2);", s[i].base);
        }
    }

    // Dump exports.
    if(h.exp_tbl_num) {
        cro_export* e = (cro_export*) (cro + h.exp_tbl_off);

        printf("\nExport Table:\n");
        uint32_t i;
        for(i=0; i<h.exp_tbl_num; i++) {
            printf("Export %d\n", i);

            uint32_t off = cro_decode_seg_offset(s, h.seg_tbl_num, e[i].data_off);

            printf("\tName offset: %s\n", cro + e[i].name_off);
            printf("\tData offset: 0x%"PRIx32"\n", off);

            if(sym_fd != NULL) {
                fprintf(sym_fd, "MakeNameEx(0x%"PRIx32", \"%s\", 0);\n", off,
                        cro + e[i].name_off);
                fprintf(sym_fd, "AutoMark(0x%"PRIx32", 30);\n", off);
            }
        }
    }

    // Dump imports.
    if(h.imp1_tbl_num) {
        cro_import* im = (cro_import*) (cro + h.imp1_tbl_off);

        printf("\nImport Table 1:\n");
        uint32_t i;
        for(i=0; i<h.imp1_tbl_num; i++) {
            printf("Import %d\n", i);

            printf("\tName offset: %s\n", cro + im[i].name_off);
            printf("\tSymbol offset: 0x%"PRIx32"\n", im[i].symbol_off);

            cro_patch* sy = (cro_patch*) (cro + im[i].symbol_off);
            size_t n = 0;
            do {
                uint32_t out_off = cro_decode_seg_offset(s, h.seg_tbl_num, sy->out_off);
                uint32_t* out = (uint32_t*) (cro + out_off);

                if(sym_fd != NULL) {
                    char name[256];
                    snprintf(name, sizeof(name), "imp_%s_%zu", cro + im[i].name_off, n);

                    fprintf(sym_fd, "MakeNameEx(0x%"PRIx32", \"%s\", 0);\n", out_off, name);
                    fprintf(sym_fd, "MakeComm(0x%"PRIx32", \"%s\");\n", out_off, cro + im[i].name_off);
                }

                printf("\t\tWrite out=%"PRIx32" type=%x x=%"PRIx32"\n",
                       out_off, (unsigned int) sy->type, sy->x);

                // XXX: keep IDA from XREF:ing all unlinked function pointers.
                if(sy->x == 0)
                    sy->x = 0xBADC0DE;

                switch(sy->type) {
                case 0:
                    break;
                case 2: // u32 absolute
                    *out = sy->x;
                    break;
                case 3:  // u32 relative TODO
                case 10: // THUMB branch TODO
                case 28: // ARM branch TODO
                case 29: // ARM branch modify TODO
                case 42: // u32 relative (weird) TODO
                    printf("ERROR: unhandled import type %x for %s\n",
                           (unsigned int) sy->type, cro + im[i].name_off);
                    break;

                default:
                    printf("ERROR: unknown import type %x for %s\n",
                           (unsigned int) sy->type, cro + im[i].name_off);
                }

                n++;
            } while(!(sy++)->is_last);
        }
    }

    if(sym_fd != NULL) {
        fprintf(sym_fd, "AnalyseArea(0x%"PRIx32", 0x%"PRIx32");", s[1].base,
                s[1].base + s[1].sz);
        fprintf(sym_fd, "}");
    }


    if(cro_binout) {
        printf("Dumping file to %s..\n", cro_binout);

        FILE* out_fd = fopen(cro_binout, "w");
        if(out_fd != NULL) {
            fwrite(cro, len, 1, out_fd);
            fclose(out_fd);
        }
        else perror("fopen");
    }
}
