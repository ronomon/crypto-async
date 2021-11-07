{
  "targets": [
    {
      "target_name": "binding",
      "sources": [ "binding.c" ],
      "defines": [ "OPENSSL_API_COMPAT=OPENSSL_CONFIGURED_API" ]
    },
    {
      "target_name": "copy",
      "type": "none",
      "dependencies": [ "binding" ],
      "copies": [
        {
          'destination': '<(module_root_dir)',
          'files': ['<(module_root_dir)/build/Release/binding.node']
        }
      ]
    }
  ]
}
