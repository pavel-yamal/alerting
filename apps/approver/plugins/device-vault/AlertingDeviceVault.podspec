Pod::Spec.new do |s|
  s.name = 'AlertingDeviceVault'
  s.version = '0.1.0'
  s.summary = 'Signing key of a decision-maker behind biometrics (alerting, ADR 0016)'
  s.license = 'Proprietary'
  s.homepage = 'https://example.invalid/alerting'
  s.author = 'alerting'
  s.source = { :git => 'https://example.invalid/alerting.git', :tag => s.version.to_s }
  s.source_files = 'ios/Sources/**/*.swift'
  s.ios.deployment_target = '15.0'
  s.dependency 'Capacitor'
  s.swift_version = '5.9'
end
