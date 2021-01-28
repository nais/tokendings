# Detekt

A static code analysis tool for the Kotlin programming language.

## Configuration

### Intellij

* In the Settings/Preferences dialog `⌘,` select Plugins. 
  * Install the plugin: [detekt](https://github.com/detekt/detekt-intellij-plugin)
  * Add `detekt/detekt-config.yml` as Configuration path. 
    
* See this: [Configuration example](https://github.com/kozmi55/Kotlin-Android-Examples/blob/master/detekt-config.yml) for more settings
  
### Github Actions

* Documentation: [detekt-all](https://github.com/marketplace/actions/detekt-all)

The action is configured with the same `detekt/detekt-config.yml` file.
Configuration runs `--build-upon-default-config` That allows additional provided configurations to override the
defaults.
