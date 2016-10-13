{
  "targets": [
    {
      "target_name": "binding",
      "sources": [ "binding.cc" ],
      "include_dirs": ["<!(node -e \"require('nan')\")"]
    }
  ]
}
