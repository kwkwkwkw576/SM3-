
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// 定义SM3初始向量
#define SM3_IV {0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, \
                0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E}

// 循环左移函数
static uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 压缩函数常量T
static const uint32_t T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

// 辅助函数FF
static uint32_t FF(uint32_t X, uint32_t Y, uint32_t Z, int j) {
    if (j < 16) return X ^ Y ^ Z;
    else return (X & Y) | (X & Z) | (Y & Z);
}

// 辅助函数GG
static uint32_t GG(uint32_t X, uint32_t Y, uint32_t Z, int j) {
    if (j < 16) return X ^ Y ^ Z;
    else return (X & Y) | (~X & Z);
}

// 置换函数P0
static uint32_t P0(uint32_t X) {
    return X ^ rotl(X, 9) ^ rotl(X, 17);
}

// 置换函数P1
static uint32_t P1(uint32_t X) {
    return X ^ rotl(X, 15) ^ rotl(X, 23);
}

// 消息扩展
static void message_extension(const uint32_t *B, uint32_t *W, uint32_t *W1) {
    int i;
    for (i = 0; i < 16; i++) {
        W[i] = B[i];
    }
    for (i = 16; i < 68; i++) {
        W[i] = P1(W[i-16] ^ W[i-9] ^ rotl(W[i-3], 15)) ^ rotl(W[i-13], 7) ^ W[i-6];
    }
    for (i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i+4];
    }
}

// 压缩函数
static void cf(uint32_t *V, const uint32_t *B) {
    uint32_t W[68], W1[64];
    uint32_t A, B_, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int j;

    A = V[0];
    B_ = V[1];
    C = V[2];
    D = V[3];
    E = V[4];
    F = V[5];
    G = V[6];
    H = V[7];

    message_extension(B, W, W1);

    for (j = 0; j < 64; j++) {
        SS1 = rotl((rotl(A, 12) + E + rotl(T[j], j)), 7);
        SS2 = SS1 ^ rotl(A, 12);
        TT1 = FF(A, B_, C, j) + D + SS2 + W1[j];
        TT2 = GG(E, F, G, j) + H + SS1 + W[j];
        
        D = C;
        C = rotl(B_, 9);
        B_ = A;
        A = TT1;
        H = G;
        G = rotl(F, 19);
        F = E;
        E = P0(TT2);
    }

    V[0] ^= A;
    V[1] ^= B_;
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
}

// SM3哈希核心函数
void sm3_hash(const unsigned char *input, size_t input_len, unsigned char *output) {
    uint32_t V[8] = SM3_IV;
    uint32_t B[16];
    size_t len = input_len;
    size_t i;
    unsigned char buf[64];

    while (len >= 64) {
        for (i = 0; i < 16; i++) {
            B[i] = (uint32_t)input[i*4] << 24 |
                   (uint32_t)input[i*4+1] << 16 |
                   (uint32_t)input[i*4+2] << 8 |
                   (uint32_t)input[i*4+3];
        }
        cf(V, B);
        input += 64;
        len -= 64;
    }

    memset(buf, 0, 64);
    memcpy(buf, input, len);
    buf[len] = 0x80;

    if (len + 1 > 56) {
        for (i = 0; i < 16; i++) {
            B[i] = (uint32_t)buf[i*4] << 24 |
                   (uint32_t)buf[i*4+1] << 16 |
                   (uint32_t)buf[i*4+2] << 8 |
                   (uint32_t)buf[i*4+3];
        }
        cf(V, B);
        memset(buf, 0, 64);
    }

    uint64_t total_bits = (uint64_t)input_len * 8;
    buf[56] = (unsigned char)((total_bits >> 56) & 0xFF);
    buf[57] = (unsigned char)((total_bits >> 48) & 0xFF);
    buf[58] = (unsigned char)((total_bits >> 40) & 0xFF);
    buf[59] = (unsigned char)((total_bits >> 32) & 0xFF);
    buf[60] = (unsigned char)((total_bits >> 24) & 0xFF);
    buf[61] = (unsigned char)((total_bits >> 16) & 0xFF);
    buf[62] = (unsigned char)((total_bits >> 8) & 0xFF);
    buf[63] = (unsigned char)(total_bits & 0xFF);

    for (i = 0; i < 16; i++) {
        B[i] = (uint32_t)buf[i*4] << 24 |
               (uint32_t)buf[i*4+1] << 16 |
               (uint32_t)buf[i*4+2] << 8 |
               (uint32_t)buf[i*4+3];
    }
    cf(V, B);

    for (i = 0; i < 8; i++) {
        output[i*4] = (unsigned char)((V[i] >> 24) & 0xFF);
        output[i*4+1] = (unsigned char)((V[i] >> 16) & 0xFF);
        output[i*4+2] = (unsigned char)((V[i] >> 8) & 0xFF);
        output[i*4+3] = (unsigned char)(V[i] & 0xFF);
    }
}

// 主函数：支持手动输入字符串计算SM3
int main() {
    unsigned char hash[32];
    char input[1024];  // 用于存储用户输入
    int i;

    printf("请输入要计算SM3哈希的字符串（空字符串直接按回车）：\n");
    
    // 读取用户输入（支持空字符串）
    if (fgets(input, sizeof(input), stdin) == NULL) {
        printf("输入错误\n");
        return 1;
    }

    // 移除fgets自带的换行符（保持与echo -n行为一致）
    size_t input_len = strlen(input);
    if (input_len > 0 && input[input_len - 1] == '\n') {
        input[input_len - 1] = '\0';
        input_len--;
    }

    // 计算哈希
    sm3_hash((const unsigned char*)input, input_len, hash);

    // 输出结果
    printf("SM3哈希值: ");
    for (i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
	getchar();
    return 0;
}
