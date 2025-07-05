#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

using namespace std;

string docFile(const string& tenTep) {
    ifstream file(tenTep, ios::binary);
    stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

void ghiFile(const string& tenTep, const string& duLieu) {
    ofstream file(tenTep, ios::binary);
    file.write(duLieu.c_str(), duLieu.size());
}

string bamSHA256(const string& duLieu) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)duLieu.c_str(), duLieu.size(), hash);
    return string((char*)hash, SHA256_DIGEST_LENGTH);
}

string maHoaBase64(const string& duLieu) {
    BIO* bio, * b64;
    BUF_MEM* boDem;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, duLieu.data(), duLieu.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &boDem);
    string maHoa(boDem->data, boDem->length);
    BIO_free_all(bio);
    return maHoa;
}

string giaiMaBase64(const string& duLieu) {
    BIO* bio, * b64;
    int len = duLieu.size();
    char* boDem = new char[len];
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(duLieu.data(), len);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int doDaiGiaiMa = BIO_read(bio, boDem, len);
    string giaiMa(boDem, doDaiGiaiMa);
    delete[] boDem;
    BIO_free_all(bio);
    return giaiMa;
}

EVP_PKEY* taiKhoaCongKhai(const string& duongDan) {
    FILE* f = fopen(duongDan.c_str(), "r");
    EVP_PKEY* khoa = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    return khoa;
}

EVP_PKEY* taiKhoaBiMat(const string& duongDan) {
    FILE* f = fopen(duongDan.c_str(), "r");
    EVP_PKEY* khoa = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return khoa;
}

string maHoaRSA(EVP_PKEY* khoaCongKhai, const string& duLieu) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(khoaCongKhai, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    size_t doDai;
    EVP_PKEY_encrypt(ctx, NULL, &doDai, (const unsigned char*)duLieu.data(), duLieu.size());
    vector<unsigned char> out(doDai);
    EVP_PKEY_encrypt(ctx, out.data(), &doDai, (const unsigned char*)duLieu.data(), duLieu.size());
    EVP_PKEY_CTX_free(ctx);
    return string((char*)out.data(), doDai);
}

string giaiMaRSA(EVP_PKEY* khoaBiMat, const string& duLieu) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(khoaBiMat, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
    size_t doDai;
    EVP_PKEY_decrypt(ctx, NULL, &doDai, (const unsigned char*)duLieu.data(), duLieu.size());
    vector<unsigned char> out(doDai);
    EVP_PKEY_decrypt(ctx, out.data(), &doDai, (const unsigned char*)duLieu.data(), duLieu.size());
    EVP_PKEY_CTX_free(ctx);
    return string((char*)out.data(), doDai);
}

string kySoRSA(EVP_PKEY* khoaBiMat, const string& duLieu) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx;
    EVP_DigestSignInit(ctx, &pctx, EVP_sha256(), NULL, khoaBiMat);
    EVP_DigestSignUpdate(ctx, duLieu.data(), duLieu.size());
    size_t doDaiChuKy;
    EVP_DigestSignFinal(ctx, NULL, &doDaiChuKy);
    vector<unsigned char> chuKy(doDaiChuKy);
    EVP_DigestSignFinal(ctx, chuKy.data(), &doDaiChuKy);
    EVP_MD_CTX_free(ctx);
    return string((char*)chuKy.data(), doDaiChuKy);
}

bool xacThucRSA(EVP_PKEY* khoaCongKhai, const string& duLieu, const string& chuKy) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx;
    EVP_DigestVerifyInit(ctx, &pctx, EVP_sha256(), NULL, khoaCongKhai);
    EVP_DigestVerifyUpdate(ctx, duLieu.data(), duLieu.size());
    int ketQua = EVP_DigestVerifyFinal(ctx, (unsigned char*)chuKy.data(), chuKy.size());
    EVP_MD_CTX_free(ctx);
    return ketQua == 1;
}

string maHoaAES(const string& banRo, const string& khoa, string& iv) {
    iv.resize(AES_BLOCK_SIZE);
    RAND_bytes((unsigned char*)&iv[0], AES_BLOCK_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)khoa.data(), (unsigned char*)iv.data());

    vector<unsigned char> out(banRo.size() + AES_BLOCK_SIZE);
    int outLen1, outLen2;
    EVP_EncryptUpdate(ctx, out.data(), &outLen1, (unsigned char*)banRo.data(), banRo.size());
    EVP_EncryptFinal_ex(ctx, out.data() + outLen1, &outLen2);
    EVP_CIPHER_CTX_free(ctx);
    return string((char*)out.data(), outLen1 + outLen2);
}

string giaiMaAES(const string& banMa, const string& khoa, const string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)khoa.data(), (unsigned char*)iv.data());

    vector<unsigned char> out(banMa.size());
    int outLen1, outLen2;
    EVP_DecryptUpdate(ctx, out.data(), &outLen1, (unsigned char*)banMa.data(), banMa.size());
    EVP_DecryptFinal_ex(ctx, out.data() + outLen1, &outLen2);
    EVP_CIPHER_CTX_free(ctx);
    return string((char*)out.data(), outLen1 + outLen2);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Cach dung: secure_chat.exe sender|receiver\n";
        return 1;
    }

    string cheDo = argv[1];
    OpenSSL_add_all_algorithms();

    if (cheDo == "sender") {
        string thongDiep = docFile("message.txt");

        string khoaAES(32, 0);
        RAND_bytes((unsigned char*)&khoaAES[0], khoaAES.size());

        string iv, banMa = maHoaAES(thongDiep, khoaAES, iv);
        string bam = bamSHA256(iv + banMa);

        string thongTin = "UserA-session123";
        string chuKy = kySoRSA(taiKhoaBiMat("keys/sender_private.pem"), thongTin);

        string khoaAESMaHoa = maHoaRSA(taiKhoaCongKhai("keys/receiver_public.pem"), khoaAES);

        ghiFile("message.enc", maHoaBase64(iv) + "\n" +
                               maHoaBase64(banMa) + "\n" +
                               maHoaBase64(bam) + "\n" +
                               maHoaBase64(chuKy) + "\n" +
                               maHoaBase64(khoaAESMaHoa));
        cout << ">> Da gui tin nhan.\n";
    }
    else if (cheDo == "receiver") {
        ifstream f("message.enc");
        string iv_b64, banMa_b64, bam_b64, chuKy_b64, khoa_b64;
        getline(f, iv_b64);
        getline(f, banMa_b64);
        getline(f, bam_b64);
        getline(f, chuKy_b64);
        getline(f, khoa_b64);

        string iv = giaiMaBase64(iv_b64);
        string banMa = giaiMaBase64(banMa_b64);
        string bam = giaiMaBase64(bam_b64);
        string chuKy = giaiMaBase64(chuKy_b64);
        string khoaAESMaHoa = giaiMaBase64(khoa_b64);

        string xacNhan = bamSHA256(iv + banMa);
        if (xacNhan != bam) {
            cerr << "LOI: Kiem tra toan ven tin nhan that bai.\n";
            return 1;
        }

        string thongTin = "UserA-session123";
        if (!xacThucRSA(taiKhoaCongKhai("keys/sender_public.pem"), thongTin, chuKy)) {
            cerr << "LOI: Xac thuc chu ky that bai.\n";
            return 1;
        }

        string khoaAES = giaiMaRSA(taiKhoaBiMat("keys/receiver_private.pem"), khoaAESMaHoa);
        string thongDiep = giaiMaAES(banMa, khoaAES, iv);
        ghiFile("response.txt", thongDiep);

        cout << ">> Da nhan va xac thuc tin nhan.\n";
    }
    else {
        cerr << "Che do khong hop le.\n";
        return 1;
    }

    return 0;
}
