package com.bezkoder.springjwt.controllers;

import java.io.BufferedReader;

import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.bezkoder.springjwt.models.ERole;
import com.bezkoder.springjwt.models.Role;
import com.bezkoder.springjwt.models.User;
import com.bezkoder.springjwt.payload.request.LoginRequest;
import com.bezkoder.springjwt.payload.request.SignupRequest;
import com.bezkoder.springjwt.payload.response.JwtResponse;
import com.bezkoder.springjwt.payload.response.MessageResponse;
import com.bezkoder.springjwt.repository.RoleRepository;
import com.bezkoder.springjwt.repository.UserRepository;
import com.bezkoder.springjwt.security.jwt.JwtUtils;
import com.bezkoder.springjwt.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;

  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

    SecurityContextHolder.getContext().setAuthentication(authentication);
    String jwt = jwtUtils.generateJwtToken(authentication);
    
    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();    
    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    return ResponseEntity.ok(new JwtResponse(jwt, 
                         userDetails.getId(), 
                         userDetails.getUsername(), 
                         userDetails.getEmail(), 
                         roles));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(
      @RequestParam("username") String username,
      @RequestParam("email") String email,
      @RequestParam("password") String password,
      @RequestParam("role") Set<String> role,
      @RequestParam("image") MultipartFile imageFile) {

      if (userRepository.existsByUsername(username)) {
          return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
      }

      if (userRepository.existsByEmail(email)) {
          return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
      }

      // Save the image file and get the path
      String imagePath = saveImage(imageFile);

      // Create new user's account
      User user = new User(username, email, encoder.encode(password), imagePath);

      Set<Role> roles = new HashSet<>();
      if (role == null) {
          Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                  .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(userRole);
      } else {
          role.forEach(r -> {
              switch (r) {
                  case "admin":
                      Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                      roles.add(adminRole);
                      break;
                  case "mod":
                      Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                      roles.add(modRole);
                      break;
                  default:
                      Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                      roles.add(userRole);
              }
          });
      }

      user.setRoles(roles);
      userRepository.save(user);

      return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

  private String saveImage(MultipartFile imageFile) {
	    try {
	        String fileName = imageFile.getOriginalFilename();
	        String filePath = "C:\\Users\\lenovo\\Downloads\\spring-boot-spring-security-jwt-authentication-master\\spring-boot-spring-security-jwt-authentication-master\\img\\" + fileName;
	        File dest = new File(filePath);
	        imageFile.transferTo(dest);
	        return imageFile.getOriginalFilename();
	    } catch (IOException e) {
	        throw new RuntimeException("Error saving image: " + e.getMessage());
	    }
	}
  @PostMapping("/facial-recognition")
  public ResponseEntity<?> performFacialRecognition(@RequestParam("image") MultipartFile imageFile) {
      try {
          // Save the uploaded image
          String uploadedImagePath = saveImage(imageFile);

          // Path to the Python script
          String pythonScriptPath = "C:\\Users\\lenovo\\Downloads\\face_reconized.py";

          // Retrieve all users
          List<User> users = userRepository.findAll();

          // Initialize variables for tracking authentication
          boolean isAuthenticated = false;
          Long authenticatedUserId = null;
          Set<Role> authenticatedUserRole = null;

          // Loop through each user and perform facial recognition
          for (User user : users) {
              String userImagePath = "C:\\Users\\lenovo\\Downloads\\spring-boot-spring-security-jwt-authentication-master\\spring-boot-spring-security-jwt-authentication-master\\img\\" + user.getImage(); // Assuming user.getPhoto() returns the filename
              String uploadPath = "C:\\Users\\lenovo\\Downloads\\spring-boot-spring-security-jwt-authentication-master\\spring-boot-spring-security-jwt-authentication-master\\img\\" + uploadedImagePath; // Assuming user.getPhoto() returns the filename

              // Command to execute the Python script for facial recognition
              String command = "python " + pythonScriptPath + " " + uploadPath + " " + userImagePath;
              System.out.println("Command: " + command);

              // Execute the command
              Process process = Runtime.getRuntime().exec(command);

              // Capture output and error streams
              BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
              BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
              StringBuilder output = new StringBuilder();
              StringBuilder errorOutput = new StringBuilder();

              String line;
              while ((line = reader.readLine()) != null) {
                  output.append(line).append("\n");
              }

              while ((line = errorReader.readLine()) != null) {
                  errorOutput.append(line).append("\n");
              }

              process.waitFor();

              // Log the output and errors
              System.out.println("Python Script Output: " + output.toString());
              if (errorOutput.length() > 0) {
                  System.err.println("Python Script Error: " + errorOutput.toString());
              }

              // Check if authentication succeeded
              if (output.toString().contains("Succes: Authentification reussie!")) {
                  isAuthenticated = true;
                  authenticatedUserId = user.getId(); // Assuming you have a method to retrieve user ID
                  authenticatedUserRole = user.getRoles(); // Assuming you have a method to retrieve user role
                  break; // Exit loop on first successful authentication
              }
          }

          // Handle authentication result
          if (isAuthenticated) {
        	    Map<String, Object> response = new HashMap<>();
        	    response.put("message", "Authentication successful.");
        	    response.put("userId", authenticatedUserId);
        	    return ResponseEntity.ok(response);
        	}else {
              return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authentication failed.");
          }
      } catch (Exception e) {
          return ResponseEntity.badRequest().body(new MessageResponse("Error during facial recognition: " + e.getMessage()));
      }
  }

  @GetMapping("/getUser/{id}")
  public ResponseEntity<?> getUserById(@PathVariable Long id) {
      Optional<User> user = userRepository.findById(id);
      if (user.isPresent()) {
          return ResponseEntity.ok(user.get());
      } else {
          return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
      }
  }


}
