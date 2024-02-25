#!/bin/bash
#
# Shell script to build the contents of the ciphersuites/ repository of yaml files.
#

function main() {
    local DIRECTORY=
    while getopts 'hd:' OPT; do
        case ${OPT} in
            h)
                printf "${0} [-h] -d DIRECTORY\n"
                printf "\t-d DIRECTORY: Directory write yaml files to.\n"
                exit 0
                ;;
            d)
                if [ ! -d "${OPTARG}" ]; then
                    printf "${0}: Directory Error: Directory '${OPTARG}' doesn't exist\n" 1>&2
                    exit 1
                fi
                DIRECTORY="${OPTARG}"
                ;;
        esac
    done

    # TODO: We should probably check for a .venv
    python -m pip install .
    python -m ciphersuites --version

    # Scrape IANA reserved ciphersuite list
    scrape-iana > "${DIRECTORY}/iana.yaml"

    # Scrape scanigma knowledge base
    scrape-scanigma > "${DIRECTORY}/scanigma_ciphers.yaml"
    # Scrape TestSSL.sh cipher-mapping.txt
    scrape-testssl > "${DIRECTORY}/testssl_ciphers.yaml"
    # Combine and deduplicate TestSSL & Scanigma lists
    deduplicate-ciphers "${DIRECTORY}/testssl_ciphers.yaml" "${DIRECTORY}/scanigma_ciphers.yaml" > "${DIRECTORY}/combined_3rd_party_ciphers.yaml"
    # Combine and deduplicate IANA & combined 3rd party lists
    deduplicate-ciphers "${DIRECTORY}/iana.yaml" "${DIRECTORY}/combined_3rd_party_ciphers.yaml" > "${DIRECTORY}/combined_iana_3rd_party_ciphers.yaml"
    # Run complete_cs_instance on combined IANA & 3rd party list
    complete-ciphersuites "${DIRECTORY}/combined_iana_3rd_party_ciphers.yaml" > "${DIRECTORY}/ciphersuites.yaml"
    # Remove unecessary 3rd party lists
    rm -f \
        "${DIRECTORY}/combined_iana_3rd_party_ciphers.yaml" \
        "${DIRECTORY}/combined_3rd_party_ciphers.yaml" \
        "${DIRECTORY}/scanigma_ciphers.yaml" \
        "${DIRECTORY}/testssl_ciphers.yaml"

    # Scrape openssl documentation and testssl cipher-mapping.txt
    scrape-openssl > "${DIRECTORY}/openssl.yaml"
    # Scrape gnutls manual
    scrape-gnutls "manual" > "${DIRECTORY}/gnutls_manual.yaml"
    # Scrape gnutls ciphersuites.c source code
    scrape-gnutls "ciphersuites.c" > "${DIRECTORY}/gnutls_source.yaml"
    # Combine and deduplicate GNUTLS lists
    deduplicate-ciphers "${DIRECTORY}/gnutls_source.yaml" "${DIRECTORY}/gnutls_manual.yaml" > "${DIRECTORY}/gnutls.yaml"
    # Remove unecessary gnutls lists
    rm -f \
        "${DIRECTORY}/gnutls_source.yaml" \
        "${DIRECTORY}/gnutls_manual.yaml"

    scrape-nss > "${DIRECTORY}/nss.yaml"
    scrape-go > "${DIRECTORY}/go.yaml"
    scrape-jsse > "${DIRECTORY}/jsse.yaml"
    scrape-libressl > "${DIRECTORY}/libressl.yaml"
    scrape-boringssl > "${DIRECTORY}/boringssl.yaml"
    scrape-s2n > "${DIRECTORY}/s2n.yaml"
}


main ${@}