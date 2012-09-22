{
    'variables': {
        # Default for this variable, to get the right behavior for
        # Node versions <= 0.6.*.
        'node_shared_openssl%': 'true'
    },
    'targets': [
        {
            'target_name': 'simple_rsa_encrypt',
            'sources': [ 'src/rsa_encrypt.cc' ],
            'conditions': [
                [ 'node_shared_openssl=="false"', {
                    'include_dirs': [
                        '<(node_root_dir)/deps/openssl/openssl/include'
                    ]
                }]
            ]
        }
    ]
}
